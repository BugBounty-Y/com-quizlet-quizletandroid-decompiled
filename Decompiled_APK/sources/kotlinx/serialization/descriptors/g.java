package kotlinx.serialization.descriptors;

import com.google.android.gms.internal.mlkit_vision_camera.U1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.C4932x;
import kotlin.collections.CollectionsKt;
import kotlin.collections.IndexedValue;
import kotlin.collections.N;
import kotlin.collections.O;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.InterfaceC5058l;

/* loaded from: classes3.dex */
public final class g implements SerialDescriptor, InterfaceC5058l {
    public final String a;
    public final U1 b;
    public final int c;
    public final List d;
    public final HashSet e;
    public final String[] f;
    public final SerialDescriptor[] g;
    public final List[] h;
    public final boolean[] i;
    public final Map j;
    public final SerialDescriptor[] k;
    public final u l;

    public g(String serialName, U1 kind, int i, List typeParameters, a builder) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(kind, "kind");
        Intrinsics.checkNotNullParameter(typeParameters, "typeParameters");
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = serialName;
        this.b = kind;
        this.c = i;
        this.d = builder.b;
        ArrayList arrayList = builder.c;
        this.e = CollectionsKt.u0(arrayList);
        String[] strArr = (String[]) arrayList.toArray(new String[0]);
        this.f = strArr;
        this.g = AbstractC5047c0.c(builder.e);
        this.h = (List[]) builder.f.toArray(new List[0]);
        this.i = CollectionsKt.r0(builder.g);
        Intrinsics.checkNotNullParameter(strArr, "<this>");
        N n = new N(new C4932x(strArr));
        ArrayList arrayList2 = new ArrayList(C.q(n, 10));
        Iterator it2 = n.iterator();
        while (true) {
            O o = (O) it2;
            if (!o.b.hasNext()) {
                this.j = V.k(arrayList2);
                this.k = AbstractC5047c0.c(typeParameters);
                this.l = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 23));
                return;
            }
            IndexedValue indexedValue = (IndexedValue) o.next();
            arrayList2.add(new Pair(indexedValue.b, Integer.valueOf(indexedValue.a)));
        }
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final String a() {
        return this.a;
    }

    @Override // kotlinx.serialization.internal.InterfaceC5058l
    public final Set b() {
        return this.e;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final int d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        Integer num = (Integer) this.j.get(name);
        if (num != null) {
            return num.intValue();
        }
        return -3;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final U1 e() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof g) {
            SerialDescriptor serialDescriptor = (SerialDescriptor) obj;
            if (Intrinsics.b(this.a, serialDescriptor.a()) && Arrays.equals(this.k, ((g) obj).k)) {
                int iF = serialDescriptor.f();
                int i = this.c;
                if (i == iF) {
                    for (int i2 = 0; i2 < i; i2++) {
                        SerialDescriptor[] serialDescriptorArr = this.g;
                        if (Intrinsics.b(serialDescriptorArr[i2].a(), serialDescriptor.i(i2).a()) && Intrinsics.b(serialDescriptorArr[i2].e(), serialDescriptor.i(i2).e())) {
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
        return this.f[i];
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List getAnnotations() {
        return this.d;
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final List h(int i) {
        return this.h[i];
    }

    public final int hashCode() {
        return ((Number) this.l.getValue()).intValue();
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final SerialDescriptor i(int i) {
        return this.g[i];
    }

    @Override // kotlinx.serialization.descriptors.SerialDescriptor
    public final boolean j(int i) {
        return this.i[i];
    }

    public final String toString() {
        return AbstractC5047c0.m(this);
    }
}
