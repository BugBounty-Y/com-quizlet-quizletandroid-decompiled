package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import com.android.billingclient.api.s;
import java.util.Collection;
import java.util.Set;
import kotlin.collections.AbstractC4919j;

/* loaded from: classes.dex */
public class c extends AbstractC4919j implements androidx.compose.runtime.external.kotlinx.collections.immutable.e {
    public static final c d = new c(n.e, 0);
    public final n b;
    public final int c;

    public c(n nVar, int i) {
        this.b = nVar;
        this.c = i;
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set a() {
        return new k(this, 0);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set b() {
        return new k(this, 1);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public boolean containsKey(Object obj) {
        return this.b.d(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final int d() {
        return this.c;
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Collection e() {
        return new m(this, 0);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.e
    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public e builder() {
        return new e(this);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public Object get(Object obj) {
        return this.b.g(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    public final c h(Object obj, androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.a aVar) {
        s sVarU = this.b.u(obj, obj != null ? obj.hashCode() : 0, aVar, 0);
        if (sVarU == null) {
            return this;
        }
        return new c((n) sVarU.c, this.c + sVarU.b);
    }
}
