package com.fasterxml.jackson.databind.introspect;

import com.fasterxml.jackson.databind.EnumNamingStrategy;
import com.fasterxml.jackson.databind.util.ClassUtil;

/* loaded from: classes.dex */
public abstract class EnumNamingStrategyFactory {
    public static EnumNamingStrategy createEnumNamingStrategyInstance(Object obj, boolean z, EnumNamingStrategy enumNamingStrategy) {
        if (obj == null) {
            return enumNamingStrategy;
        }
        if (!(obj instanceof Class)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("AnnotationIntrospector returned EnumNamingStrategy definition of type ", ClassUtil.classNameOf(obj), "; expected type `Class<EnumNamingStrategy>` instead"));
        }
        Class cls = (Class) obj;
        if (cls == EnumNamingStrategy.class) {
            return null;
        }
        if (!EnumNamingStrategy.class.isAssignableFrom(cls)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Problem with AnnotationIntrospector returned Class ", ClassUtil.classNameOf(cls), "; expected `Class<EnumNamingStrategy>`"));
        }
        if (ClassUtil.createInstance(cls, z) == null) {
            return null;
        }
        throw new ClassCastException();
    }
}
