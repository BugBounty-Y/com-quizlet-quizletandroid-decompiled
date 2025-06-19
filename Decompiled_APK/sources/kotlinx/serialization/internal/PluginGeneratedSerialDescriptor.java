package kotlinx.serialization.internal;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public class PluginGeneratedSerialDescriptor implements SerialDescriptor, InterfaceC5058l {
    public final String a;
    public final D b;
    public final int c;
    public int d;
    public final String[] e;
    public final List[] f;
    public final boolean[] g;
    public Object h;
    public final Object i;
    public final Object j;
    public final Object k;

    public PluginGeneratedSerialDescriptor(String serialName, D d, int i) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        this.a = serialName;
        this.b = d;
        this.c = i;
        this.d = -1;
        String[] strArr = new String[i];
        for (int i2 = 0; i2 < i; i2++) {
            strArr[i2] = "[UNINITIALIZED]";
        }
        this.e = strArr;
        int i3 = this.c;
        this.f = new List[i3];
        this.g = new boolean[i3];
        this.h = kotlin.collections.V.c();
        kotlin.m mVar = kotlin.m.b;
        final int i4 = 0;
        this.i = kotlin.l.a(mVar, new Function0(this) { // from class: kotlinx.serialization.internal.d0
            public final /* synthetic */ PluginGeneratedSerialDescriptor b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                KSerializer[] kSerializerArrChildSerializers;
                ArrayList arrayList;
                KSerializer[] kSerializerArrTypeParametersSerializers;
                switch (i4) {
                    case 0:
                        D d2 = this.b.b;
                        return (d2 == null || (kSerializerArrChildSerializers = d2.childSerializers()) == null) ? AbstractC5047c0.b : kSerializerArrChildSerializers;
                    case 1:
                        D d3 = this.b.b;
                        if (d3 == null || (kSerializerArrTypeParametersSerializers = d3.typeParametersSerializers()) == null) {
                            arrayList = null;
                        } else {
                            arrayList = new ArrayList(kSerializerArrTypeParametersSerializers.length);
                            for (KSerializer kSerializer : kSerializerArrTypeParametersSerializers) {
                                arrayList.add(kSerializer.getDescriptor());
                            }
                        }
                        return AbstractC5047c0.c(arrayList);
                    default:
                        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = this.b;
                        return Integer.valueOf(AbstractC5047c0.f(pluginGeneratedSerialDescriptor, (SerialDescriptor[]) pluginGeneratedSerialDescriptor.j.getValue()));
                }
            }
        });
        final int i5 = 1;
        this.j = kotlin.l.a(mVar, new Function0(this) { // from class: kotlinx.serialization.internal.d0
            public final /* synthetic */ PluginGeneratedSerialDescriptor b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                KSerializer[] kSerializerArrChildSerializers;
                ArrayList arrayList;
                KSerializer[] kSerializerArrTypeParametersSerializers;
                switch (i5) {
                    case 0:
                        D d2 = this.b.b;
                        return (d2 == null || (kSerializerArrChildSerializers = d2.childSerializers()) == null) ? AbstractC5047c0.b : kSerializerArrChildSerializers;
                    case 1:
                        D d3 = this.b.b;
                        if (d3 == null || (kSerializerArrTypeParametersSerializers = d3.typeParametersSerializers()) == null) {
                            arrayList = null;
                        } else {
                            arrayList = new ArrayList(kSerializerArrTypeParametersSerializers.length);
                            for (KSerializer kSerializer : kSerializerArrTypeParametersSerializers) {
                                arrayList.add(kSerializer.getDescriptor());
                            }
                        }
                        return AbstractC5047c0.c(arrayList);
                    default:
                        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = this.b;
                        return Integer.valueOf(AbstractC5047c0.f(pluginGeneratedSerialDescriptor, (SerialDescriptor[]) pluginGeneratedSerialDescriptor.j.getValue()));
                }
            }
        });
        final int i6 = 2;
        this.k = kotlin.l.a(mVar, new Function0(this) { // from class: kotlinx.serialization.internal.d0
            public final /* synthetic */ PluginGeneratedSerialDescriptor b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, kotlin.k] */
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                KSerializer[] kSerializerArrChildSerializers;
                ArrayList arrayList;
                KSerializer[] kSerializerArrTypeParametersSerializers;
                switch (i6) {
                    case 0:
                        D d2 = this.b.b;
                        return (d2 == null || (kSerializerArrChildSerializers = d2.childSerializers()) == null) ? AbstractC5047c0.b : kSerializerArrChildSerializers;
                    case 1:
                        D d3 = this.b.b;
                        if (d3 == null || (kSerializerArrTypeParametersSerializers = d3.typeParametersSerializers()) == null) {
                            arrayList = null;
                        } else {
                            arrayList = new ArrayList(kSerializerArrTypeParametersSerializers.length);
                            for (KSerializer kSerializer : kSerializerArrTypeParametersSerializers) {
                                arrayList.add(kSerializer.getDescriptor());
                            }
                        }
                        return AbstractC5047c0.c(arrayList);
                    default:
                        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = this.b;
                        return Integer.valueOf(AbstractC5047c0.f(pluginGeneratedSerialDescriptor, (SerialDescriptor[]) pluginGeneratedSerialDescriptor.j.getValue()));
                }
            }
        });
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String a() {
        return this.a;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, java.util.Map] */
    @Override // kotlinx.serialization.internal.InterfaceC5058l
    public final Set b() {
        return this.h.keySet();
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Map] */
    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        Integer num = (Integer) this.h.get(name);
        if (num != null) {
            return num.intValue();
        }
        return -3;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public U1 e() {
        return kotlinx.serialization.descriptors.j.b;
    }

    /* JADX WARN: Type inference failed for: r2v2, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r6v3, types: [java.lang.Object, kotlin.k] */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof PluginGeneratedSerialDescriptor) {
            SerialDescriptor serialDescriptor = (SerialDescriptor) obj;
            if (Intrinsics.b(this.a, serialDescriptor.a()) && Arrays.equals((SerialDescriptor[]) this.j.getValue(), (SerialDescriptor[]) ((PluginGeneratedSerialDescriptor) obj).j.getValue())) {
                int iF = serialDescriptor.f();
                int i = this.c;
                if (i == iF) {
                    for (int i2 = 0; i2 < i; i2++) {
                        if (Intrinsics.b(i(i2).a(), serialDescriptor.i(i2).a()) && Intrinsics.b(i(i2).e(), serialDescriptor.i(i2).e())) {
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int f() {
        return this.c;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String g(int i) {
        return this.e[i];
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List getAnnotations() {
        return kotlin.collections.K.a;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List h(int i) {
        List list = this.f[i];
        return list == null ? kotlin.collections.K.a : list;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    public int hashCode() {
        return ((Number) this.k.getValue()).intValue();
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public SerialDescriptor i(int i) {
        return ((KSerializer[]) this.i.getValue())[i].getDescriptor();
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean j(int i) {
        return this.g[i];
    }

    public final void k(String name, boolean z) {
        Intrinsics.checkNotNullParameter(name, "name");
        int i = this.d + 1;
        this.d = i;
        String[] strArr = this.e;
        strArr[i] = name;
        this.g[i] = z;
        this.f[i] = null;
        if (i == this.c - 1) {
            HashMap map = new HashMap();
            int length = strArr.length;
            for (int i2 = 0; i2 < length; i2++) {
                map.put(strArr[i2], Integer.valueOf(i2));
            }
            this.h = map;
        }
    }

    public String toString() {
        return AbstractC5047c0.m(this);
    }
}
