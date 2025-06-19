package kotlin.jvm.internal;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.jvm.internal.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4950i implements kotlin.reflect.c, InterfaceC4948g {

    @NotNull
    public static final C4949h b = new C4949h(null);
    public static final Map c;
    public static final HashMap d;
    public static final LinkedHashMap e;
    public final Class a;

    static {
        List listJ = kotlin.collections.B.j(Function0.class, Function1.class, Function2.class, kotlin.jvm.functions.c.class, kotlin.jvm.functions.d.class, kotlin.jvm.functions.e.class, kotlin.jvm.functions.f.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, kotlin.jvm.functions.a.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, androidx.compose.runtime.internal.b.class, kotlin.jvm.functions.b.class);
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listJ, 10));
        int i = 0;
        for (Object obj : listJ) {
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            arrayList.add(new Pair((Class) obj, Integer.valueOf(i)));
            i = i2;
        }
        c = V.k(arrayList);
        HashMap map = new HashMap();
        map.put("boolean", "kotlin.Boolean");
        map.put("char", "kotlin.Char");
        map.put("byte", "kotlin.Byte");
        map.put("short", "kotlin.Short");
        map.put("int", "kotlin.Int");
        map.put("float", "kotlin.Float");
        map.put("long", "kotlin.Long");
        map.put("double", "kotlin.Double");
        HashMap map2 = new HashMap();
        map2.put("java.lang.Boolean", "kotlin.Boolean");
        map2.put("java.lang.Character", "kotlin.Char");
        map2.put("java.lang.Byte", "kotlin.Byte");
        map2.put("java.lang.Short", "kotlin.Short");
        map2.put("java.lang.Integer", "kotlin.Int");
        map2.put("java.lang.Float", "kotlin.Float");
        map2.put("java.lang.Long", "kotlin.Long");
        map2.put("java.lang.Double", "kotlin.Double");
        HashMap map3 = new HashMap();
        map3.put("java.lang.Object", "kotlin.Any");
        map3.put("java.lang.String", "kotlin.String");
        map3.put("java.lang.CharSequence", "kotlin.CharSequence");
        map3.put("java.lang.Throwable", "kotlin.Throwable");
        map3.put("java.lang.Cloneable", "kotlin.Cloneable");
        map3.put("java.lang.Number", "kotlin.Number");
        map3.put("java.lang.Comparable", "kotlin.Comparable");
        map3.put("java.lang.Enum", "kotlin.Enum");
        map3.put("java.lang.annotation.Annotation", "kotlin.Annotation");
        map3.put("java.lang.Iterable", "kotlin.collections.Iterable");
        map3.put("java.util.Iterator", "kotlin.collections.Iterator");
        map3.put("java.util.Collection", "kotlin.collections.Collection");
        map3.put("java.util.List", "kotlin.collections.List");
        map3.put("java.util.Set", "kotlin.collections.Set");
        map3.put("java.util.ListIterator", "kotlin.collections.ListIterator");
        map3.put("java.util.Map", "kotlin.collections.Map");
        map3.put("java.util.Map$Entry", "kotlin.collections.Map.Entry");
        map3.put("kotlin.jvm.internal.StringCompanionObject", "kotlin.String.Companion");
        map3.put("kotlin.jvm.internal.EnumCompanionObject", "kotlin.Enum.Companion");
        map3.putAll(map);
        map3.putAll(map2);
        Collection<String> collectionValues = map.values();
        Intrinsics.checkNotNullExpressionValue(collectionValues, "<get-values>(...)");
        for (String str : collectionValues) {
            StringBuilder sb = new StringBuilder("kotlin.jvm.internal.");
            Intrinsics.d(str);
            sb.append(StringsKt.c0(str, str, '.'));
            sb.append("CompanionObject");
            map3.put(sb.toString(), str.concat(".Companion"));
        }
        for (Map.Entry entry : c.entrySet()) {
            map3.put(((Class) entry.getKey()).getName(), "kotlin.Function" + ((Number) entry.getValue()).intValue());
        }
        d = map3;
        LinkedHashMap linkedHashMap = new LinkedHashMap(kotlin.collections.U.a(map3.size()));
        for (Map.Entry entry2 : map3.entrySet()) {
            Object key = entry2.getKey();
            String str2 = (String) entry2.getValue();
            linkedHashMap.put(key, StringsKt.c0(str2, str2, '.'));
        }
        e = linkedHashMap;
    }

    public C4950i(Class jClass) {
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        this.a = jClass;
    }

    @Override // kotlin.jvm.internal.InterfaceC4948g
    public final Class c() {
        return this.a;
    }

    public final String e() {
        String str;
        b.getClass();
        Class jClass = this.a;
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        String strConcat = null;
        if (jClass.isAnonymousClass() || jClass.isLocalClass()) {
            return null;
        }
        boolean zIsArray = jClass.isArray();
        HashMap map = d;
        if (!zIsArray) {
            String str2 = (String) map.get(jClass.getName());
            return str2 == null ? jClass.getCanonicalName() : str2;
        }
        Class<?> componentType = jClass.getComponentType();
        if (componentType.isPrimitive() && (str = (String) map.get(componentType.getName())) != null) {
            strConcat = str.concat("Array");
        }
        return strConcat == null ? "kotlin.Array" : strConcat;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof C4950i) && kotlin.jvm.a.c(this).equals(kotlin.jvm.a.c((kotlin.reflect.c) obj));
    }

    public final String f() {
        String str;
        b.getClass();
        Class jClass = this.a;
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        String strConcat = null;
        if (jClass.isAnonymousClass()) {
            return null;
        }
        if (!jClass.isLocalClass()) {
            boolean zIsArray = jClass.isArray();
            LinkedHashMap linkedHashMap = e;
            if (!zIsArray) {
                String str2 = (String) linkedHashMap.get(jClass.getName());
                return str2 == null ? jClass.getSimpleName() : str2;
            }
            Class<?> componentType = jClass.getComponentType();
            if (componentType.isPrimitive() && (str = (String) linkedHashMap.get(componentType.getName())) != null) {
                strConcat = str.concat("Array");
            }
            return strConcat == null ? "Array" : strConcat;
        }
        String simpleName = jClass.getSimpleName();
        Method enclosingMethod = jClass.getEnclosingMethod();
        if (enclosingMethod != null) {
            String strB0 = StringsKt.b0(simpleName, enclosingMethod.getName() + '$');
            if (strB0 != null) {
                return strB0;
            }
        }
        Constructor<?> enclosingConstructor = jClass.getEnclosingConstructor();
        if (enclosingConstructor == null) {
            return StringsKt.a0(simpleName, simpleName, '$');
        }
        return StringsKt.b0(simpleName, enclosingConstructor.getName() + '$');
    }

    public final boolean g(Object obj) {
        b.getClass();
        Class jClass = this.a;
        Intrinsics.checkNotNullParameter(jClass, "jClass");
        Map map = c;
        Intrinsics.e(map, "null cannot be cast to non-null type kotlin.collections.Map<K of kotlin.collections.MapsKt__MapsKt.get, V of kotlin.collections.MapsKt__MapsKt.get>");
        Integer num = (Integer) map.get(jClass);
        if (num != null) {
            return O.e(num.intValue(), obj);
        }
        if (jClass.isPrimitive()) {
            Intrinsics.checkNotNullParameter(jClass, "<this>");
            jClass = kotlin.jvm.a.c(K.a(jClass));
        }
        return jClass.isInstance(obj);
    }

    public final int hashCode() {
        return kotlin.jvm.a.c(this).hashCode();
    }

    public final String toString() {
        return this.a.toString() + " (Kotlin reflection is not available)";
    }
}
