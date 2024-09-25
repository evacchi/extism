use core::slice;
use std::{
    ffi::{c_void, CStr},
    ptr::{addr_of, null_mut},
};

use extism::{
    sdk::{*},
    CurrentPlugin, Function, Plugin, UserData, ValType,
};
use jni_simple::*;
use libc::c_char;
use wasmtime::Val;

use crate::{
    extism_version,
    sdk::{
        extism_function_set_namespace, extism_plugin_cancel, extism_plugin_cancel_handle,
        extism_plugin_config, extism_plugin_free, extism_plugin_new_error_free, val_as_raw,
    },
    CancelHandle,
};

static mut JVM: Option<JavaVM> = Option::None;

#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {
    JVM = Some(vm);
    return JNI_VERSION_1_8;
}

unsafe fn vm() -> JavaVM {
    JVM.expect("The JavaVM reference was not initialized")
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1function_1new(
    env: JNIEnv,
    _this: jobject,
    name: jstring,
    raw_input_types: jintArray,
    n_inputs: jint,
    raw_output_types: jintArray,
    n_outputs: jint,
    callback: jobject,
    user_data: jobject,
    _free_user_data: jlong,
) -> jlong {
    let inputs_arr = env.GetIntArrayElements(raw_input_types, null_mut());
    let outputs_arr = env.GetIntArrayElements(raw_output_types, null_mut());

    let input_slice = slice::from_raw_parts(inputs_arr, n_inputs as usize);
    let output_slice = slice::from_raw_parts(outputs_arr, n_outputs as usize);

    let mut input_types = vec![ValType::I32; n_inputs as usize];
    let mut output_types = vec![ValType::I32; n_outputs as usize];
    let mut i = 0;
    for ele in input_slice {
        input_types[i] = conv(*ele);
        i += 1;
    }

    i = 0;
    for ele in output_slice {
        output_types[i] = conv(*ele);
        i += 1;
    }

    let name: String =
        match std::ffi::CStr::from_ptr(env.GetStringUTFChars(name, null_mut())).to_str() {
            Ok(x) => x.to_string(),
            Err(_) => {
                return 0;
            }
        };

    let cback = env.NewGlobalRef(callback) as u64;

    let user_data: UserData<()> = UserData::new_pointer(user_data, None); // FIXME
    let f = Function::new(
        name.clone(),
        input_types,
        output_types.clone(),
        user_data,
        move |plugin, inputs, outputs, user_data| {
            let store = &*plugin.store;
            let inputs: Vec<_> = inputs.iter().map(|x| val_as_raw(x, store)).collect();
            let mut output_tmp: Vec<_> = vec![0u64; n_outputs as usize];

            // We cannot simply "get" the Vec's storage pointer because
            // the underlying storage might be invalid when the Vec is empty.
            // In that case, we return (null, 0).

            let (inputs_ptr, inputs_len) = if inputs.is_empty() {
                (core::ptr::null(), 0 as Size)
            } else {
                (inputs.as_ptr(), inputs.len() as Size)
            };

            let (output_ptr, output_len) = if output_tmp.is_empty() {
                (null_mut(), 0 as Size)
            } else {
                (output_tmp.as_mut_ptr(), output_tmp.len() as Size)
            };

            let env = vm().GetEnv(JNI_VERSION_1_8).unwrap();

            let clazz = env.FindClass_str("org/extism/sdk/LibExtism0$InternalExtismFunction");
            let method_id = env.GetMethodID_str(clazz, "invoke", "(J[JI[JIJ)V");

            let p: jtype = (addr_of!(*plugin) as jlong).into();
            let in_arr = env.NewLongArray(inputs_len as i32);
            env.SetLongArrayRegion(in_arr, 0, inputs_len as i32, inputs_ptr as *const i64);

            let out_arr = env.NewLongArray(output_len as i32);
            env.SetLongArrayRegion(out_arr, 0, output_len as i32, output_ptr as *const i64);

            let d = addr_of!(user_data) as i64;

            env.CallVoidMethodA(
                cback as jobject,
                method_id,
                [
                    p,
                    in_arr.into(),
                    (inputs_len as i32).into(),
                    out_arr.into(),
                    (output_len as i32).into(),
                    d.into(),
                ]
                .as_mut_ptr(),
            );

            if !output_ptr.is_null() {
                env.GetLongArrayRegion(out_arr, 0, output_len as i32, output_ptr as *mut i64);
                let outs = slice::from_raw_parts(output_ptr, output_len as usize);

                for i in 0..output_len {
                    let iu = i as usize;
                    let t = &output_types[iu];
                    let v = outs[iu];
                    match t {
                        ValType::I32 => outputs[iu] = Val::I32(v as i32),
                        ValType::I64 => outputs[iu] = Val::I64(v as i64),
                        ValType::F32 => outputs[iu] = Val::F32(v as u32),
                        ValType::F64 => outputs[iu] = Val::F64(v as u64),
                        _ => todo!(),
                    }
                }
            }

            println!("outputs: {:?}", outputs);

            Ok(())
        },
    );
    Box::into_raw(Box::new(ExtismFunction(std::cell::Cell::new(Some(f))))) as jlong
}

fn conv(i: i32) -> ValType {
    match i {
        0 => ValType::I32,
        1 => ValType::I64,
        2 => ValType::F32,
        3 => ValType::F64,
        4 => ValType::V128,
        5 => ValType::FuncRef,
        6 => ValType::ExternRef,
        _ => panic!("Unknown value"),
    }
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_function_free
 * Signature: (J)V
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1function_1free(
    _env: JNIEnv,
    _this: jobject,
    func_ptr: jlong,
) {
    extism_function_free(func_ptr as *mut ExtismFunction);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory_1length(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    n: jlong,
) -> jint {
    return extism_current_plugin_memory_length(
        plugin_ptr as *mut CurrentPlugin,
        n as ExtismMemoryHandle,
    ) as i32;
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory(
    env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    off: jlong,
    sz: jlong,
) -> jobject {
    let p: *mut u8 =
        extism_current_plugin_memory(plugin_ptr as *mut CurrentPlugin).add(off as usize);
    println!("mem {:}", p as i64);
    return env.NewDirectByteBuffer(p as *mut c_void, sz);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory_1alloc(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    n: jlong,
) -> jlong {
    return extism_current_plugin_memory_alloc(plugin_ptr as *mut CurrentPlugin, n as Size)
        as jlong;
}
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory_1free(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    ptr: jlong,
) {
    extism_current_plugin_memory_free(plugin_ptr as *mut CurrentPlugin, ptr as ExtismMemoryHandle);
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_log_file
 * Signature: (Ljava/lang/String;Ljava/lang/String;)Z
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1log_1file(
    _env: JNIEnv,
    _this: jobject,
    _path: jstring,
    _log_level: jstring,
) -> jboolean {
    return true;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_error
 * Signature: (J)Ljava/lang/String;
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1error(
    env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) -> jstring {
    let chars = extism_plugin_error(plugin_ptr as *mut Plugin);
    env.NewStringUTF(chars)
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_new
 * Signature: ([BJ[JIZ[J)J
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1new(
    env: JNIEnv,
    _this: jobject,
    wasm: jbyteArray,
    wasm_size: jlong,
    function_ptrs: jlongArray,
    n_funcs: jint,
    wasi: jboolean,
    errmsg: jobjectArray,
) -> jlong {
    let mut err: *mut i8 = null_mut();

    let p = extism_plugin_new(
        env.GetByteArrayElements(wasm, null_mut()) as *const u8,
        wasm_size as u64,
        env.GetLongArrayElements(function_ptrs, null_mut()) as *mut *const ExtismFunction,
        n_funcs as u64,
        wasi,
        &mut err,
    );

    if !err.is_null() {
        let s = env.NewStringUTF(err);
        env.SetObjectArrayElement(errmsg, 0, s);
        extism_plugin_new_error_free(err);
    }

    return p as jlong;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_new_with_fuel_limit
 * Signature: ([BJ[JIZJ[J)J
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1new_1with_1fuel_1limit(
    env: JNIEnv,
    _this: jobject,
    wasm: jbyteArray,
    wasm_size: jlong,
    function_ptrs: jlongArray,
    n_funcs: jint,
    wasi: jboolean,
    fuel: jlong,
    errmsg: jlongArray,
) -> jlong {
    return extism_plugin_new_with_fuel_limit(
        env.GetByteArrayElements(wasm, null_mut()) as *const u8,
        wasm_size as u64,
        function_ptrs as *mut *const ExtismFunction,
        n_funcs as u64,
        wasi,
        fuel as u64,
        errmsg as *mut *mut i8,
    ) as jlong;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_new_error_get
 * Signature: (J)Ljava/lang/String;
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1new_1error_1get(
    env: JNIEnv,
    _this: jobject,
    err: jlong,
) -> jstring {
    let errp = err as *mut c_char;
    return env.NewStringUTF(errp);
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_new_error_free
 * Signature: (J)V
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1new_1error_1free(
    _env: JNIEnv,
    _this: jobject,
    errmsg: jlong,
) {
    extism_plugin_new_error_free(errmsg as *mut c_char);
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_version
 * Signature: ()Ljava/lang/String;
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1version(
    env: JNIEnv,
    _this: jobject,
) -> jstring {
    let v = extism_version();
    return env.NewStringUTF_str(v);
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_call
 * Signature: (Lcom/sun/jna/Pointer;Ljava/lang/String;[BI)I
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1call(
    env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    function_name: jstring,
    data: jbyteArray,
    data_len: jint,
) -> jint {
    let chars = env.GetStringUTFChars(function_name, null_mut());
    let fname = CStr::from_ptr(chars);
    println!("{:?}", fname.to_str());

    return extism_plugin_call(
        plugin_ptr as *mut Plugin,
        chars,
        env.GetByteArrayElements(data, null_mut()) as *const u8,
        data_len as u64,
    );
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_output_length
 * Signature: (J)I
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1output_1length(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) -> jint {
    return extism_plugin_output_length(plugin_ptr as *mut Plugin) as i32;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_output_data
 * Signature: (J)J
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1output_1data(
    env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) -> jbyteArray {
    let p = plugin_ptr as *mut Plugin;
    let res = extism_plugin_output_data(p);
    let len = extism_plugin_output_length(p);

    println!("output {:?} {}", res, len);

    if len == 0 {
        return null_mut();
    };
    let arr = env.NewByteArray(len as jsize);
    env.SetByteArrayRegion(arr, 0, len as jsize, res as *const i8);

    return arr;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_free
 * Signature: (J)V
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1free(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) {
    extism_plugin_free(plugin_ptr as *mut Plugin);
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_config
 * Signature: (J[BI)Z
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1config(
    env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    json: jbyteArray,
    json_len: jint,
) -> jboolean {
    let mut buf = vec![0i8; json_len as usize];
    env.GetByteArrayRegion(json, 0, json_len as i32, buf.as_mut_ptr());
    extism_plugin_config(
        plugin_ptr as *mut Plugin,
        buf.as_ptr() as *const u8,
        json_len as u64,
    )
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_cancel_handle
 * Signature: (J)J
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1cancel_1handle(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) -> jlong {
    extism_plugin_cancel_handle(plugin_ptr as *const Plugin) as jlong
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_cancel
 * Signature: (J)Z
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1cancel(
    _env: JNIEnv,
    _this: jobject,
    cancel_handle: jlong,
) -> jboolean {
    extism_plugin_cancel(cancel_handle as *const CancelHandle)
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_function_set_namespace
 * Signature: (JLjava/lang/String;)V
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1function_1set_1namespace(
    env: JNIEnv,
    _this: jobject,
    p: jlong,
    name: jstring,
) {
    let namespace = env.GetStringUTFChars(name, null_mut());
    extism_function_set_namespace(p as *mut ExtismFunction, namespace);
}
