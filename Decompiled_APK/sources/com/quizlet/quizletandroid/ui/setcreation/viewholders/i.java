package com.quizlet.quizletandroid.ui.setcreation.viewholders;

/* loaded from: classes3.dex */
public final class i implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ m b;

    public /* synthetic */ i(m mVar, int i) {
        this.a = i;
        this.b = mVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                this.b.f = ((Boolean) obj).booleanValue();
                break;
            default:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                m mVar = (m) this.b.k.b;
                boolean z = !zBooleanValue;
                mVar.h().getEditText().setFocusableInTouchMode(z);
                mVar.f().getEditText().setFocusableInTouchMode(z);
                break;
        }
    }
}
