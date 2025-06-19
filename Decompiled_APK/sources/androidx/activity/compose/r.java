package androidx.activity.compose;

import androidx.activity.C0030b;
import androidx.activity.D;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class r extends D {
    public C d;
    public Function2 e;
    public com.bumptech.glide.manager.p f;
    public boolean g;

    @Override // androidx.activity.D
    public final void a() {
        com.bumptech.glide.manager.p pVar = this.f;
        if (pVar != null) {
            pVar.e();
        }
        com.bumptech.glide.manager.p pVar2 = this.f;
        if (pVar2 != null) {
            pVar2.a = false;
        }
        this.g = false;
    }

    @Override // androidx.activity.D
    public final void b() {
        com.bumptech.glide.manager.p pVar = this.f;
        if (pVar != null && !pVar.a) {
            pVar.e();
            this.f = null;
        }
        if (this.f == null) {
            this.f = new com.bumptech.glide.manager.p(this.d, false, this.e, this);
        }
        com.bumptech.glide.manager.p pVar2 = this.f;
        if (pVar2 != null) {
            ((kotlinx.coroutines.channels.h) pVar2.b).i(null);
        }
        com.bumptech.glide.manager.p pVar3 = this.f;
        if (pVar3 != null) {
            pVar3.a = false;
        }
        this.g = false;
    }

    @Override // androidx.activity.D
    public final void c(C0030b c0030b) {
        super.c(c0030b);
        com.bumptech.glide.manager.p pVar = this.f;
        if (pVar != null) {
            ((kotlinx.coroutines.channels.h) pVar.b).o(c0030b);
        }
    }

    @Override // androidx.activity.D
    public final void d(C0030b c0030b) {
        super.d(c0030b);
        com.bumptech.glide.manager.p pVar = this.f;
        if (pVar != null) {
            pVar.e();
        }
        if (this.a) {
            this.f = new com.bumptech.glide.manager.p(this.d, true, this.e, this);
        }
        this.g = true;
    }
}
