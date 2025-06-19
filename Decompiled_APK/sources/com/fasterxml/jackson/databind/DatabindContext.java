package com.fasterxml.jackson.databind;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.ObjectIdGenerator;
import com.fasterxml.jackson.annotation.ObjectIdResolver;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.ObjectIdInfo;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.ClassUtil;
import com.fasterxml.jackson.databind.util.Converter;
import java.lang.reflect.Type;

/* loaded from: classes.dex */
public abstract class DatabindContext {
    private JavaType _resolveAndValidateGeneric(JavaType javaType, String str, PolymorphicTypeValidator polymorphicTypeValidator, int i) throws JsonMappingException, IllegalArgumentException {
        MapperConfig<?> config = getConfig();
        PolymorphicTypeValidator.Validity validityValidateSubClassName = polymorphicTypeValidator.validateSubClassName(config, javaType, str.substring(0, i));
        if (validityValidateSubClassName == PolymorphicTypeValidator.Validity.DENIED) {
            return (JavaType) _throwSubtypeNameNotAllowed(javaType, str, polymorphicTypeValidator);
        }
        JavaType javaTypeConstructFromCanonical = getTypeFactory().constructFromCanonical(str);
        if (!javaTypeConstructFromCanonical.isTypeOrSubTypeOf(javaType.getRawClass())) {
            return (JavaType) _throwNotASubtype(javaType, str);
        }
        PolymorphicTypeValidator.Validity validity = PolymorphicTypeValidator.Validity.ALLOWED;
        return (validityValidateSubClassName == validity || polymorphicTypeValidator.validateSubType(config, javaType, javaTypeConstructFromCanonical) == validity) ? javaTypeConstructFromCanonical : (JavaType) _throwSubtypeClassNotAllowed(javaType, str, polymorphicTypeValidator);
    }

    public String _colonConcat(String str, String str2) {
        return str2 == null ? str : a.l(str, ": ", str2);
    }

    public final String _format(String str, Object... objArr) {
        return objArr.length > 0 ? String.format(str, objArr) : str;
    }

    public String _quotedString(String str) {
        return str == null ? "[N/A]" : a.B("\"", _truncate(str), "\"");
    }

    public <T> T _throwNotASubtype(JavaType javaType, String str) throws JsonMappingException {
        throw invalidTypeIdException(javaType, str, "Not a subtype");
    }

    public <T> T _throwSubtypeClassNotAllowed(JavaType javaType, String str, PolymorphicTypeValidator polymorphicTypeValidator) throws JsonMappingException {
        throw invalidTypeIdException(javaType, str, "Configured `PolymorphicTypeValidator` (of type " + ClassUtil.classNameOf(polymorphicTypeValidator) + ") denied resolution");
    }

    public <T> T _throwSubtypeNameNotAllowed(JavaType javaType, String str, PolymorphicTypeValidator polymorphicTypeValidator) throws JsonMappingException {
        throw invalidTypeIdException(javaType, str, "Configured `PolymorphicTypeValidator` (of type " + ClassUtil.classNameOf(polymorphicTypeValidator) + ") denied resolution");
    }

    public final String _truncate(String str) {
        if (str == null) {
            return "";
        }
        if (str.length() <= 500) {
            return str;
        }
        return str.substring(0, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR) + "]...[" + str.substring(str.length() - com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
    }

    public JavaType constructType(Type type) {
        if (type == null) {
            return null;
        }
        return getTypeFactory().constructType(type);
    }

    public Converter<Object, Object> converterInstance(Annotated annotated, Object obj) throws JsonMappingException {
        if (obj == null) {
            return null;
        }
        if (obj instanceof Converter) {
            return (Converter) obj;
        }
        if (!(obj instanceof Class)) {
            throw new IllegalStateException("AnnotationIntrospector returned Converter definition of type " + obj.getClass().getName() + "; expected type Converter or Class<Converter> instead");
        }
        Class cls = (Class) obj;
        if (cls == Converter.None.class || ClassUtil.isBogusClass(cls)) {
            return null;
        }
        if (!Converter.class.isAssignableFrom(cls)) {
            throw new IllegalStateException(assistantMode.refactored.a.i(cls, new StringBuilder("AnnotationIntrospector returned Class "), "; expected Class<Converter>"));
        }
        MapperConfig<?> config = getConfig();
        config.getHandlerInstantiator();
        return (Converter) ClassUtil.createInstance(cls, config.canOverrideAccessModifiers());
    }

    public abstract MapperConfig<?> getConfig();

    public abstract TypeFactory getTypeFactory();

    public abstract JsonMappingException invalidTypeIdException(JavaType javaType, String str, String str2);

    public ObjectIdGenerator<?> objectIdGeneratorInstance(Annotated annotated, ObjectIdInfo objectIdInfo) throws JsonMappingException {
        Class<? extends ObjectIdGenerator<?>> generatorType = objectIdInfo.getGeneratorType();
        MapperConfig<?> config = getConfig();
        config.getHandlerInstantiator();
        return ((ObjectIdGenerator) ClassUtil.createInstance(generatorType, config.canOverrideAccessModifiers())).forScope(objectIdInfo.getScope());
    }

    public ObjectIdResolver objectIdResolverInstance(Annotated annotated, ObjectIdInfo objectIdInfo) {
        Class<? extends ObjectIdResolver> resolverType = objectIdInfo.getResolverType();
        MapperConfig<?> config = getConfig();
        config.getHandlerInstantiator();
        if (ClassUtil.createInstance(resolverType, config.canOverrideAccessModifiers()) == null) {
            return null;
        }
        throw new ClassCastException();
    }

    public abstract <T> T reportBadDefinition(JavaType javaType, String str) throws JsonMappingException;

    public <T> T reportBadDefinition(Class<?> cls, String str) throws JsonMappingException {
        return (T) reportBadDefinition(constructType(cls), str);
    }

    public JavaType resolveAndValidateSubType(JavaType javaType, String str, PolymorphicTypeValidator polymorphicTypeValidator) throws JsonMappingException, IllegalArgumentException {
        int iIndexOf = str.indexOf(60);
        if (iIndexOf > 0) {
            return _resolveAndValidateGeneric(javaType, str, polymorphicTypeValidator, iIndexOf);
        }
        MapperConfig<?> config = getConfig();
        PolymorphicTypeValidator.Validity validityValidateSubClassName = polymorphicTypeValidator.validateSubClassName(config, javaType, str);
        if (validityValidateSubClassName == PolymorphicTypeValidator.Validity.DENIED) {
            return (JavaType) _throwSubtypeNameNotAllowed(javaType, str, polymorphicTypeValidator);
        }
        try {
            Class<?> clsFindClass = getTypeFactory().findClass(str);
            if (!javaType.isTypeOrSuperTypeOf(clsFindClass)) {
                return (JavaType) _throwNotASubtype(javaType, str);
            }
            JavaType javaTypeConstructSpecializedType = config.getTypeFactory().constructSpecializedType(javaType, clsFindClass);
            return (validityValidateSubClassName != PolymorphicTypeValidator.Validity.INDETERMINATE || polymorphicTypeValidator.validateSubType(config, javaType, javaTypeConstructSpecializedType) == PolymorphicTypeValidator.Validity.ALLOWED) ? javaTypeConstructSpecializedType : (JavaType) _throwSubtypeClassNotAllowed(javaType, str, polymorphicTypeValidator);
        } catch (ClassNotFoundException unused) {
            return null;
        } catch (Exception e) {
            throw invalidTypeIdException(javaType, str, a.m("problem: (", e.getClass().getName(), ") ", ClassUtil.exceptionMessage(e)));
        }
    }
}
