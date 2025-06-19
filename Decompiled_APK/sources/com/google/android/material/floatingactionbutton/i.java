package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import com.google.android.gms.internal.mlkit_vision_common.Z3;

/* loaded from: classes2.dex */
public final class i extends AnimatorListenerAdapter {
    public boolean a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c c;
    public final /* synthetic */ q d;

    public i(q qVar, boolean z, com.quizlet.data.repository.qclass.c cVar) {
        this.d = qVar;
        this.b = z;
        this.c = cVar;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animator) {
        this.a = true;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        q qVar = this.d;
        qVar.r = 0;
        qVar.l = null;
        if (this.a) {
            return;
        }
        boolean z = this.b;
        qVar.v.a(z ? 8 : 4, z);
        com.quizlet.data.repository.qclass.c cVar = this.c;
        if (cVar != null) {
            ((Z3) cVar.b).a((FloatingActionButton) cVar.c);
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        q qVar = this.d;
        qVar.v.a(0, this.b);
        qVar.r = 1;
        qVar.l = animator;
        this.a = false;
    }
}
