use core::slice;
use std::{cell::{Cell, OnceCell}, ffi::{c_void, CStr, CString}, io::{stdout, Write}, ptr::{addr_of, null, null_mut}, sync::OnceLock, thread::{self, panicking}, time::Duration};

use extism::{sdk::{self, extism_current_plugin_memory, extism_current_plugin_memory_alloc, extism_current_plugin_memory_free, extism_current_plugin_memory_length, extism_function_free, extism_function_new, extism_plugin_call, extism_plugin_error, extism_plugin_new, extism_plugin_new_with_fuel_limit, extism_plugin_output_data, extism_plugin_output_length, ExtismFunction, ExtismFunctionType, ExtismMemoryHandle, ExtismVal, Size}, CurrentPlugin, Function, Plugin, UserData, ValType};
use jni_simple::{*};
use wasmtime::Val;

use crate::sdk::{val_as_raw, ValUnion};



// (JNIEnv *, jobject, jstring, jintArray, jint, jintArray, jint, jobject, jobject, jlong);

static jvm: OnceLock<JavaVM> = OnceLock::new();

#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {

    use std::io::Write; // <--- bring the trait into scope

    //Optional: Only needed if you need to spawn "rust" threads that need to interact with the JVM.
    jni_simple::init_dynamic_link(JNI_CreateJavaVM as *mut c_void, JNI_GetCreatedJavaVMs as *mut c_void);

    //All error codes are jint, never JNI_OK. See JNI documentation for their meaning when you handle them.
    //This is a Result<JNIEnv, jint>.
    let env : JNIEnv = vm.GetEnv(JNI_VERSION_1_8).unwrap();
    jvm.set(vm);


    //This code does not check for failure or exceptions checks or "checks" for success in general.
    let sys = env.FindClass_str("java/lang/System");
    let nano_time = env.GetStaticMethodID_str(sys, "nanoTime", "()J");
    let nanos = env.CallStaticLongMethodA(sys, nano_time, null());
    println!("RUST: JNI_OnLoad {}", nanos);
    stdout().flush().unwrap();

    return JNI_VERSION_1_8;
}

struct DecoratedData{
    callback: jobject,
    userdata: jobject
}


#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1function_1new(
  env: JNIEnv, _this: jobject, name: jstring, raw_input_types: jintArray, n_inputs: jint, 
  raw_output_types: jintArray, n_outputs: jint, callback: jobject, user_data: jobject, free_user_data: jlong) -> jlong {


    let inputs_arr = env.GetIntArrayElements(raw_input_types, null_mut());
    let outputs_arr = env.GetIntArrayElements(raw_output_types, null_mut());

    let input_slice = slice::from_raw_parts(inputs_arr, n_inputs as usize);
    let output_slice = slice::from_raw_parts(outputs_arr, n_outputs as usize);

    let mut input_types = vec![ValType::I32; n_inputs as usize];
    let mut output_types = vec![ValType::I32; n_outputs as usize];
    let mut i = 0;
    for ele in input_slice {
        input_types[i] = conv(*ele);
        i+=1;
    }

    i=0;
    for ele in output_slice {
      output_types[i] = conv(*ele); 
      i+=1;
    }



    let g = env.NewGlobalRef(callback);

    let data = DecoratedData {
        callback: g,
        userdata: user_data
    };


    let boxed_data = Box::new(data);
    let name: String = match std::ffi::CStr::from_ptr(env.GetStringUTFChars(name, null_mut())).to_str() {
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
            let inputs: Vec<_> = inputs
                .iter()
                .map(|x| val_as_raw(x, store))
                .collect();
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

            let env = jvm.get().unwrap().GetEnv(JNI_VERSION_1_8).unwrap();

            let sys = env.FindClass_str("java/lang/System");
            let nano_time = env.GetStaticMethodID_str(sys, "nanoTime", "()J");
            let nanos = env.CallStaticLongMethodA(sys, nano_time, null());
            println!("RUST: JNI callback {} {}", name.clone(), nanos);    
            stdout().flush().unwrap();
        
            let clazz = env.FindClass_str("org/extism/sdk/LibExtism0$InternalExtismFunction");
            let method_id = env.GetMethodID_str(clazz, "invoke", "(J[JI[JIJ)V");
    
            let p: jtype = (addr_of!(plugin) as jlong).into();
            let in_arr = env.NewLongArray(inputs_len as i32);
            env.SetLongArrayRegion(in_arr, 0, inputs_len as i32, inputs_ptr as *const i64);

            let out_arr = env.NewLongArray(output_len as i32);
            env.SetLongArrayRegion(out_arr, 0, output_len as i32, output_ptr as *const i64);

            let d = addr_of!(user_data) as i64;

            env.CallVoidMethodA(cback as jobject, method_id, [p, in_arr.into(), 
                (inputs_len as i32).into(), out_arr.into(), (output_len as i32).into(), d.into()].as_mut_ptr());


            // func(
            //     plugin,
            //     inputs_ptr,
            //     inputs_len,
            //     output_ptr,
            //     output_len,
            //     user_data.as_ptr(),
            // );
            

            // for (tmp, out) in output_tmp.iter().zip(outputs.iter_mut()) {
            //     match tmp.t {
            //         ValType::I32 => *out = Val::I32(tmp.v.i32),
            //         ValType::I64 => *out = Val::I64(tmp.v.i64),
            //         ValType::F32 => *out = Val::F32(tmp.v.f32 as u32),
            //         ValType::F64 => *out = Val::F64(tmp.v.f64 as u64),
            //         _ => todo!(),
            //     }
            // }
            Ok(())
        },
    );
    Box::into_raw(Box::new(ExtismFunction(std::cell::Cell::new(Some(f))))) as jlong
}


fn conv(i:i32) -> ValType {
    match i  {
        0 => ValType::I32,
        1 => ValType::I64,
        2 => ValType::F32,
        3 => ValType::F64,
        4 => ValType::V128,
        5 => ValType::FuncRef,
        6 => ValType::ExternRef,
        _ => panic!("Unknown value")
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
    return extism_current_plugin_memory_length(plugin_ptr as *mut CurrentPlugin, n as ExtismMemoryHandle) as i32;
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
) -> jlong {
    return extism_current_plugin_memory(plugin_ptr as *mut CurrentPlugin) as i64
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory_1alloc(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    n: jlong,
) -> jlong {
    return extism_current_plugin_memory_alloc(plugin_ptr as *mut CurrentPlugin, n as sdk::Size) as i64;
}
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1current_1plugin_1memory_1free(
    _env: JNIEnv,
    _this: jobject,
    plugin_ptr: jlong,
    ptr: jlong) {
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
    errmsg: jlongArray,
) -> jlong {
    return extism_plugin_new(
      env.GetByteArrayElements(wasm, null_mut()) as *const u8, wasm_size as u64, 
      env.GetLongArrayElements(function_ptrs, null_mut()) as *mut *const ExtismFunction, n_funcs as u64, 
      wasi, errmsg as *mut*mut i8) as jlong
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
    env.GetByteArrayElements(wasm, null_mut()) as *const u8, wasm_size as u64, 
    function_ptrs as *mut *const ExtismFunction, n_funcs as u64, 
    wasi,
    fuel as u64,
    errmsg as *mut*mut i8) as jlong
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
    _errmsg: jlong,
) {
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_version
 * Signature: ()Ljava/lang/String;
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1version(
    _env: JNIEnv,
    _this: jobject,
) -> jstring {
    return null_mut();
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
      data_len as u64);
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
    _plugin_ptr: jlong,
) -> jlong {
    return 0;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_plugin_config
 * Signature: (J[BI)Z
 */

#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1plugin_1config(
    _env: JNIEnv,
    _this: jobject,
    _plugin_ptr: jlong,
    _json: jbyteArray,
    _json_len: jint,
) -> jboolean {
    return true;
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
    _plugin_ptr: jlong,
) -> jlong {
    return 0;
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
    _cancel_handle: jlong,
) -> jboolean {
    return true;
}

/*
 * Class:     org_extism_sdk_LibExtism0
 * Method:    extism_function_set_namespace
 * Signature: (JLjava/lang/String;)V
 */
#[no_mangle]
pub unsafe extern "system" fn Java_org_extism_sdk_LibExtism0_extism_1function_1set_1namespace(
    _env: JNIEnv,
    _this: jobject,
    _p: jlong,
    _name: jstring,
) {
}
