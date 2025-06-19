package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_common.Z3;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class j extends AnimatorListenerAdapter {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public j(boolean z, View view, View view2) {
        this.b = z;
        this.c = view;
        this.d = view2;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animator) {
        switch (this.a) {
            case 0:
                q qVar = (q) this.d;
                qVar.r = 0;
                qVar.l = null;
                com.quizlet.data.repository.qclass.c cVar = (com.quizlet.data.repository.qclass.c) this.c;
                if (cVar != null) {
                    ((Z3) cVar.b).b();
                    break;
                }
                break;
            default:
                if (!this.b) {
                    ((View) this.c).setVisibility(4);
                    View view = (View) this.d;
                    view.setAlpha(1.0f);
                    view.setVisibility(0);
                    break;
                }
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animator) {
        switch (this.a) {
            case 0:
                q qVar = (q) this.d;
                qVar.v.a(0, this.b);
                qVar.r = 2;
                qVar.l = animator;
                break;
            default:
                if (this.b) {
                    ((View) this.c).setVisibility(0);
                    View view = (View) this.d;
                    view.setAlpha(DefinitionKt.NO_Float_VALUE);
                    view.setVisibility(4);
                    break;
                }
                break;
        }
    }

    public j(q qVar, boolean z, com.quizlet.data.repository.qclass.c cVar) {
        this.d = qVar;
        this.b = z;
        this.c = cVar;
    }
}
