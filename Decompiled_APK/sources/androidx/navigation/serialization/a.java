package androidx.navigation.serialization;

import android.os.Bundle;
import androidx.navigation.AbstractC1285g;
import androidx.navigation.M;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends AbstractC1285g {
    public final M q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Class type) {
        super(true);
        Intrinsics.checkNotNullParameter(type, "type");
        this.q = new M(type);
    }

    @Override // androidx.navigation.S
    public final Object a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        Object obj = bundle.get(key);
        if (obj instanceof List) {
            return (List) obj;
        }
        return null;
    }

    @Override // androidx.navigation.S
    public final String b() {
        return "List<" + this.q.b() + "}>";
    }

    @Override // androidx.navigation.S
    public final Object c(Object obj, String value) {
        List list = (List) obj;
        Intrinsics.checkNotNullParameter(value, "value");
        M m = this.q;
        if (list != null) {
            Intrinsics.checkNotNullParameter(value, "value");
            return CollectionsKt.c0(list, A.b(m.d(value)));
        }
        Intrinsics.checkNotNullParameter(value, "value");
        return A.b(m.d(value));
    }

    @Override // androidx.navigation.S
    public final Object d(String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        return A.b(this.q.d(value));
    }

    @Override // androidx.navigation.S
    public final void e(Bundle bundle, String key, Object obj) {
        List list = (List) obj;
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        Intrinsics.checkNotNullParameter(key, "key");
        bundle.putSerializable(key, list != null ? new ArrayList(list) : null);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        return Intrinsics.b(this.q, ((a) obj).q);
    }

    @Override // androidx.navigation.S
    public final boolean g(Object obj, Object obj2) {
        List list = (List) obj;
        List list2 = (List) obj2;
        return Intrinsics.b(list != null ? new ArrayList(list) : null, list2 != null ? new ArrayList(list2) : null);
    }

    @Override // androidx.navigation.AbstractC1285g
    public final Object h() {
        return K.a;
    }

    public final int hashCode() {
        return this.q.q.hashCode();
    }

    @Override // androidx.navigation.AbstractC1285g
    public final List i(Object obj) {
        List list = (List) obj;
        if (list == null) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(((Enum) it2.next()).toString());
        }
        return arrayList;
    }
}
