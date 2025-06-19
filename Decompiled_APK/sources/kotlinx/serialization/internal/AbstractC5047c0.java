package kotlinx.serialization.internal;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.MissingFieldException;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* renamed from: kotlinx.serialization.internal.c0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5047c0 {
    public static final SerialDescriptor[] a = new SerialDescriptor[0];
    public static final KSerializer[] b = new KSerializer[0];
    public static final Object c = new Object();

    public static final G a(String name, KSerializer primitiveSerializer) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(primitiveSerializer, "primitiveSerializer");
        return new G(name, new H(primitiveSerializer));
    }

    public static final Set b(SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        if (serialDescriptor instanceof InterfaceC5058l) {
            return ((InterfaceC5058l) serialDescriptor).b();
        }
        HashSet hashSet = new HashSet(serialDescriptor.f());
        int iF = serialDescriptor.f();
        for (int i = 0; i < iF; i++) {
            hashSet.add(serialDescriptor.g(i));
        }
        return hashSet;
    }

    public static final SerialDescriptor[] c(List list) {
        SerialDescriptor[] serialDescriptorArr;
        if (list == null || list.isEmpty()) {
            list = null;
        }
        return (list == null || (serialDescriptorArr = (SerialDescriptor[]) list.toArray(new SerialDescriptor[0])) == null) ? a : serialDescriptorArr;
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x00c4, code lost:
    
        r13 = null;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x01b2 A[Catch: NoSuchFieldException -> 0x01b5, TRY_LEAVE, TryCatch #3 {NoSuchFieldException -> 0x01b5, blocks: (B:83:0x0179, B:85:0x0186, B:94:0x01a2, B:96:0x01a8, B:98:0x01ae, B:100:0x01b2, B:90:0x019a), top: B:123:0x0179 }] */
    /* JADX WARN: Removed duplicated region for block: B:102:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x01b9  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0179 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x019d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:143:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0186 A[Catch: NoSuchFieldException -> 0x01b5, TryCatch #3 {NoSuchFieldException -> 0x01b5, blocks: (B:83:0x0179, B:85:0x0186, B:94:0x01a2, B:96:0x01a8, B:98:0x01ae, B:100:0x01b2, B:90:0x019a), top: B:123:0x0179 }] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01ad  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final kotlinx.serialization.KSerializer d(kotlin.reflect.c r16, kotlinx.serialization.KSerializer... r17) throws java.lang.IllegalAccessException, java.lang.SecurityException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 490
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.serialization.internal.AbstractC5047c0.d(kotlin.reflect.c, kotlinx.serialization.KSerializer[]):kotlinx.serialization.KSerializer");
    }

    public static final C5071z e(String serialName, Enum[] values) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(values, "values");
        return new C5071z(serialName, values);
    }

    public static final int f(SerialDescriptor serialDescriptor, SerialDescriptor[] typeParams) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(typeParams, "typeParams");
        int iHashCode = (serialDescriptor.a().hashCode() * 31) + Arrays.hashCode(typeParams);
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        int iF = serialDescriptor.f();
        int i = 1;
        while (true) {
            int iHashCode2 = 0;
            if (!(iF > 0)) {
                break;
            }
            int i2 = iF - 1;
            int i3 = i * 31;
            String strA = serialDescriptor.i(serialDescriptor.f() - iF).a();
            if (strA != null) {
                iHashCode2 = strA.hashCode();
            }
            i = i3 + iHashCode2;
            iF = i2;
        }
        int iF2 = serialDescriptor.f();
        int iHashCode3 = 1;
        while (true) {
            if (!(iF2 > 0)) {
                return (((iHashCode * 31) + i) * 31) + iHashCode3;
            }
            int i4 = iF2 - 1;
            int i5 = iHashCode3 * 31;
            U1 u1E = serialDescriptor.i(serialDescriptor.f() - iF2).e();
            iHashCode3 = i5 + (u1E != null ? u1E.hashCode() : 0);
            iF2 = i4;
        }
    }

    public static final KSerializer g(Object obj, KSerializer... kSerializerArr) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Class[] clsArr;
        try {
            if (kSerializerArr.length == 0) {
                clsArr = new Class[0];
            } else {
                int length = kSerializerArr.length;
                Class[] clsArr2 = new Class[length];
                for (int i = 0; i < length; i++) {
                    clsArr2[i] = KSerializer.class;
                }
                clsArr = clsArr2;
            }
            Object objInvoke = obj.getClass().getDeclaredMethod("serializer", (Class[]) Arrays.copyOf(clsArr, clsArr.length)).invoke(obj, Arrays.copyOf(kSerializerArr, kSerializerArr.length));
            if (objInvoke instanceof KSerializer) {
                return (KSerializer) objInvoke;
            }
            return null;
        } catch (NoSuchMethodException unused) {
            return null;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause == null) {
                throw e;
            }
            String message = cause.getMessage();
            if (message == null) {
                message = e.getMessage();
            }
            throw new InvocationTargetException(cause, message);
        }
    }

    public static final boolean h(kotlin.reflect.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        return kotlin.jvm.a.b(cVar).isInterface();
    }

    public static final kotlin.reflect.c i(kotlin.reflect.o oVar) {
        Intrinsics.checkNotNullParameter(oVar, "<this>");
        kotlin.reflect.d dVarD = oVar.d();
        if (dVarD instanceof kotlin.reflect.c) {
            return (kotlin.reflect.c) dVarD;
        }
        if (!(dVarD instanceof kotlin.reflect.p)) {
            throw new IllegalArgumentException("Only KClass supported as classifier, got " + dVarD);
        }
        throw new IllegalArgumentException("Captured type parameter " + dVarD + " from generic non-reified function. Such functionality cannot be supported because " + dVarD + " is erased, either specify serializer explicitly or make calling function inline with reified " + dVarD + '.');
    }

    public static final void j(kotlin.reflect.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        String className = ((C4950i) cVar).f();
        if (className == null) {
            className = "<local class name not available>";
        }
        Intrinsics.checkNotNullParameter(className, "className");
        throw new SerializationException("Serializer for class '" + className + "' is not found.\nPlease ensure that class is marked as '@Serializable' and that the serialization compiler plugin is applied.\n");
    }

    public static final void k(int i, int i2, SerialDescriptor descriptor) {
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        ArrayList missingFields = new ArrayList();
        int i3 = (~i) & i2;
        for (int i4 = 0; i4 < 32; i4++) {
            if ((i3 & 1) != 0) {
                missingFields.add(descriptor.g(i4));
            }
            i3 >>>= 1;
        }
        String serialName = descriptor.a();
        Intrinsics.checkNotNullParameter(missingFields, "missingFields");
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        throw new MissingFieldException(missingFields, missingFields.size() == 1 ? androidx.compose.ui.node.B.j(new StringBuilder("Field '"), (String) missingFields.get(0), "' is required for type with serial name '", serialName, "', but it was missing") : "Fields " + missingFields + " are required for type with serial name '" + serialName + "', but they were missing", null);
    }

    public static final void l(String str, kotlin.reflect.c baseClass) {
        String string;
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        StringBuilder sb = new StringBuilder("in the polymorphic scope of '");
        C4950i c4950i = (C4950i) baseClass;
        sb.append(c4950i.f());
        sb.append('\'');
        String string2 = sb.toString();
        if (str == null) {
            string = androidx.compose.ui.node.B.h("Class discriminator was missing and no default serializers were registered ", string2, '.');
        } else {
            StringBuilder sbH = AbstractC0147y.h("Serializer for subclass '", str, "' is not found ", string2, ".\nCheck if class with serial name '");
            androidx.compose.ui.node.B.u(sbH, str, "' exists and serializer is registered in a corresponding SerializersModule.\nTo be registered automatically, class '", str, "' has to be '@Serializable', and the base class '");
            sbH.append(c4950i.f());
            sbH.append("' has to be sealed and '@Serializable'.");
            string = sbH.toString();
        }
        throw new SerializationException(string);
    }

    public static final String m(SerialDescriptor serialDescriptor) {
        Intrinsics.checkNotNullParameter(serialDescriptor, "<this>");
        return CollectionsKt.S(kotlin.ranges.l.h(0, serialDescriptor.f()), ", ", serialDescriptor.a() + '(', ")", new com.quizlet.ui.compose.modifiers.b(serialDescriptor, 17), 24);
    }
}
