package com.quizlet.quizletandroid.ui.setcreation.fragments;

/* loaded from: classes3.dex */
public final class e implements io.reactivex.rxjava3.functions.d {
    public static final e b = new e(0);
    public static final e c = new e(1);
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                timber.log.c.a.e((Throwable) obj);
                break;
            default:
                timber.log.c.a.e((Throwable) obj);
                break;
        }
    }
}
