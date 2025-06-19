package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.content.DialogInterface;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.setcreation.navigation.d b;

    public /* synthetic */ b(com.quizlet.quizletandroid.ui.setcreation.navigation.d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        com.quizlet.quizletandroid.ui.setcreation.navigation.d dVar = this.b;
        switch (this.a) {
            case 0:
                String str = EditSetFragment.J;
                dVar.d.invoke();
                break;
            default:
                String str2 = EditSetFragment.J;
                dVar.e.invoke();
                break;
        }
    }
}
