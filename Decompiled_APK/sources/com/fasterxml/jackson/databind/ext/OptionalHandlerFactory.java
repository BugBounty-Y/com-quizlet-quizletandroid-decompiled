package com.fasterxml.jackson.databind.ext;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.ser.std.DateSerializer;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.ExceptionUtil;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/* loaded from: classes.dex */
public class OptionalHandlerFactory implements Serializable {
    private static final Java7Handlers _jdk7Helper;
    public static final OptionalHandlerFactory instance;
    private final Map<String, String> _sqlDeserializers;
    private final Map<String, Object> _sqlSerializers;
    private static final Class<?> CLASS_DOM_NODE = Node.class;
    private static final Class<?> CLASS_DOM_DOCUMENT = Document.class;

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 3 */
    static {
        Java7Handlers java7HandlersInstance = null;
        try {
            java7HandlersInstance = Java7Handlers.instance();
        } catch (Throwable th) {
            ExceptionUtil.rethrowIfFatal(th);
        }
        _jdk7Helper = java7HandlersInstance;
        instance = new OptionalHandlerFactory();
    }

    public OptionalHandlerFactory() {
        HashMap map = new HashMap();
        this._sqlDeserializers = map;
        map.put("java.sql.Date", "com.fasterxml.jackson.databind.deser.std.DateDeserializers$SqlDateDeserializer");
        map.put("java.sql.Timestamp", "com.fasterxml.jackson.databind.deser.std.DateDeserializers$TimestampDeserializer");
        HashMap map2 = new HashMap();
        this._sqlSerializers = map2;
        map2.put("java.sql.Timestamp", DateSerializer.instance);
        map2.put("java.sql.Date", "com.fasterxml.jackson.databind.ser.std.SqlDateSerializer");
        map2.put("java.sql.Time", "com.fasterxml.jackson.databind.ser.std.SqlTimeSerializer");
        map2.put("java.sql.Blob", "com.fasterxml.jackson.databind.ext.SqlBlobSerializer");
        map2.put("javax.sql.rowset.serial.SerialBlob", "com.fasterxml.jackson.databind.ext.SqlBlobSerializer");
    }

    private boolean _IsXOfY(Class<?> cls, Class<?> cls2) {
        return cls2 != null && cls2.isAssignableFrom(cls);
    }

    private boolean hasSuperClassStartingWith(Class<?> cls, String str) {
        do {
            cls = cls.getSuperclass();
            if (cls == null || cls == Object.class) {
                return false;
            }
        } while (!cls.getName().startsWith(str));
        return true;
    }

    private Object instantiate(String str, JavaType javaType) throws Error, RuntimeException {
        try {
            return instantiate(Class.forName(str), javaType);
        } catch (Throwable th) {
            ExceptionUtil.rethrowIfFatal(th);
            StringBuilder sbY = a.y("Failed to find class `", str, "` for handling values of type ");
            sbY.append(ClassUtil.getTypeDescription(javaType));
            sbY.append(", problem: (");
            sbY.append(th.getClass().getName());
            sbY.append(") ");
            sbY.append(th.getMessage());
            throw new IllegalStateException(sbY.toString());
        }
    }

    public JsonDeserializer<?> findDeserializer(JavaType javaType, DeserializationConfig deserializationConfig, BeanDescription beanDescription) throws JsonMappingException {
        JsonDeserializer<?> deserializerForJavaNioFilePath;
        Class<?> rawClass = javaType.getRawClass();
        Java7Handlers java7Handlers = _jdk7Helper;
        if (java7Handlers != null && (deserializerForJavaNioFilePath = java7Handlers.getDeserializerForJavaNioFilePath(rawClass)) != null) {
            return deserializerForJavaNioFilePath;
        }
        if (_IsXOfY(rawClass, CLASS_DOM_NODE)) {
            return (JsonDeserializer) instantiate("com.fasterxml.jackson.databind.ext.DOMDeserializer$NodeDeserializer", javaType);
        }
        if (_IsXOfY(rawClass, CLASS_DOM_DOCUMENT)) {
            return (JsonDeserializer) instantiate("com.fasterxml.jackson.databind.ext.DOMDeserializer$DocumentDeserializer", javaType);
        }
        String name = rawClass.getName();
        String str = this._sqlDeserializers.get(name);
        if (str != null) {
            return (JsonDeserializer) instantiate(str, javaType);
        }
        if ((name.startsWith("javax.xml.") || hasSuperClassStartingWith(rawClass, "javax.xml.")) && instantiate("com.fasterxml.jackson.databind.ext.CoreXMLDeserializers", javaType) != null) {
            throw new ClassCastException();
        }
        return null;
    }

    public JsonSerializer<?> findSerializer(SerializationConfig serializationConfig, JavaType javaType, BeanDescription beanDescription) {
        JsonSerializer<?> serializerForJavaNioFilePath;
        Class<?> rawClass = javaType.getRawClass();
        if (_IsXOfY(rawClass, CLASS_DOM_NODE)) {
            return (JsonSerializer) instantiate("com.fasterxml.jackson.databind.ext.DOMSerializer", javaType);
        }
        Java7Handlers java7Handlers = _jdk7Helper;
        if (java7Handlers != null && (serializerForJavaNioFilePath = java7Handlers.getSerializerForJavaNioFilePath(rawClass)) != null) {
            return serializerForJavaNioFilePath;
        }
        String name = rawClass.getName();
        Object obj = this._sqlSerializers.get(name);
        if (obj != null) {
            return obj instanceof JsonSerializer ? (JsonSerializer) obj : (JsonSerializer) instantiate((String) obj, javaType);
        }
        if ((name.startsWith("javax.xml.") || hasSuperClassStartingWith(rawClass, "javax.xml.")) && instantiate("com.fasterxml.jackson.databind.ext.CoreXMLSerializers", javaType) != null) {
            throw new ClassCastException();
        }
        return null;
    }

    private Object instantiate(Class<?> cls, JavaType javaType) throws Error, RuntimeException {
        try {
            return ClassUtil.createInstance(cls, false);
        } catch (Throwable th) {
            ExceptionUtil.rethrowIfFatal(th);
            throw new IllegalStateException("Failed to create instance of `" + cls.getName() + "` for handling values of type " + ClassUtil.getTypeDescription(javaType) + ", problem: (" + th.getClass().getName() + ") " + th.getMessage());
        }
    }
}
