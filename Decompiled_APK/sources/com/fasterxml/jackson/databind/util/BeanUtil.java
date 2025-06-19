package com.fasterxml.jackson.databind.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JavaType;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/* loaded from: classes.dex */
public abstract class BeanUtil {
    /* JADX WARN: Removed duplicated region for block: B:32:0x007e  */
    /* JADX WARN: Removed duplicated region for block: B:35:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String checkUnsupportedType(com.fasterxml.jackson.databind.cfg.MapperConfig<?> r4, com.fasterxml.jackson.databind.JavaType r5) {
        /*
            java.lang.Class r0 = r5.getRawClass()
            java.lang.String r0 = r0.getName()
            boolean r1 = isJava8TimeClass(r0)
            r2 = 0
            if (r1 == 0) goto L35
            r1 = 46
            r3 = 10
            int r0 = r0.indexOf(r1, r3)
            if (r0 < 0) goto L1a
            return r2
        L1a:
            java.lang.Class<java.lang.Throwable> r0 = java.lang.Throwable.class
            boolean r0 = r5.isTypeOrSubTypeOf(r0)
            if (r0 == 0) goto L23
            return r2
        L23:
            com.fasterxml.jackson.databind.MapperFeature r0 = com.fasterxml.jackson.databind.MapperFeature.REQUIRE_HANDLERS_FOR_JAVA8_TIMES
            if (r4 == 0) goto L2f
            boolean r4 = r4.isEnabled(r0)
            if (r4 == 0) goto L2e
            goto L2f
        L2e:
            return r2
        L2f:
            java.lang.String r4 = "Java 8 date/time"
            java.lang.String r1 = "com.fasterxml.jackson.datatype:jackson-datatype-jsr310"
        L33:
            r2 = r0
            goto L57
        L35:
            boolean r1 = isJodaTimeClass(r0)
            if (r1 == 0) goto L40
            java.lang.String r4 = "Joda date/time"
            java.lang.String r1 = "com.fasterxml.jackson.datatype:jackson-datatype-joda"
            goto L57
        L40:
            boolean r0 = isJava8OptionalClass(r0)
            if (r0 == 0) goto L8b
            com.fasterxml.jackson.databind.MapperFeature r0 = com.fasterxml.jackson.databind.MapperFeature.REQUIRE_HANDLERS_FOR_JAVA8_OPTIONALS
            if (r4 == 0) goto L52
            boolean r4 = r4.isEnabled(r0)
            if (r4 == 0) goto L51
            goto L52
        L51:
            return r2
        L52:
            java.lang.String r4 = "Java 8 optional"
            java.lang.String r1 = "com.fasterxml.jackson.datatype:jackson-datatype-jdk8"
            goto L33
        L57:
            java.lang.String r5 = com.fasterxml.jackson.databind.util.ClassUtil.getTypeDescription(r5)
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            r0.append(r4)
            java.lang.String r4 = " type "
            r0.append(r4)
            r0.append(r5)
            java.lang.String r4 = " not supported by default: add Module \""
            r0.append(r4)
            r0.append(r1)
            java.lang.String r4 = "\" to enable handling"
            r0.append(r4)
            java.lang.String r4 = r0.toString()
            if (r2 == 0) goto L8a
            java.lang.String r5 = r2.name()
            java.lang.String r0 = " (or disable `MapperFeature."
            java.lang.String r1 = "`)"
            java.lang.String r4 = androidx.compose.ui.node.B.i(r4, r0, r5, r1)
        L8a:
            return r4
        L8b:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.fasterxml.jackson.databind.util.BeanUtil.checkUnsupportedType(com.fasterxml.jackson.databind.cfg.MapperConfig, com.fasterxml.jackson.databind.JavaType):java.lang.String");
    }

    public static Object getDefaultValue(JavaType javaType) {
        Class<?> rawClass = javaType.getRawClass();
        Class<?> clsPrimitiveType = ClassUtil.primitiveType(rawClass);
        if (clsPrimitiveType != null) {
            return ClassUtil.defaultValue(clsPrimitiveType);
        }
        if (javaType.isContainerType() || javaType.isReferenceType()) {
            return JsonInclude.Include.NON_EMPTY;
        }
        if (rawClass == String.class) {
            return "";
        }
        if (javaType.isTypeOrSubTypeOf(Date.class)) {
            return new Date(0L);
        }
        if (!javaType.isTypeOrSubTypeOf(Calendar.class)) {
            return null;
        }
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        gregorianCalendar.setTimeInMillis(0L);
        return gregorianCalendar;
    }

    private static boolean isJava8OptionalClass(String str) {
        return str.startsWith("java.util.Optional");
    }

    private static boolean isJava8TimeClass(String str) {
        return str.startsWith("java.time.");
    }

    private static boolean isJodaTimeClass(String str) {
        return str.startsWith("org.joda.time.");
    }
}
