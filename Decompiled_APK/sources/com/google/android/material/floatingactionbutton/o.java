package com.google.android.material.floatingactionbutton;

/* loaded from: classes2.dex */
public final class o extends p {
    public final /* synthetic */ int e;
    public final /* synthetic */ s f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o(s sVar, int i) {
        super(sVar);
        this.e = i;
        this.f = sVar;
    }

    @Override // com.google.android.material.floatingactionbutton.p
    public final float a() {
        switch (this.e) {
            case 0:
                s sVar = this.f;
                return sVar.h + sVar.i;
            case 1:
                s sVar2 = this.f;
                return sVar2.h + sVar2.j;
            default:
                return this.f.h;
        }
    }
}
