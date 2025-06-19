package com.google.android.material.snackbar;

import android.view.MotionEvent;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.google.android.material.behavior.SwipeDismissBehavior;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class BaseTransientBottomBar$Behavior extends SwipeDismissBehavior<View> {
    public final com.google.android.gms.auth.api.signin.internal.h i;

    public BaseTransientBottomBar$Behavior() {
        com.google.android.gms.auth.api.signin.internal.h hVar = new com.google.android.gms.auth.api.signin.internal.h(29);
        this.f = Math.min(Math.max(DefinitionKt.NO_Float_VALUE, 0.1f), 1.0f);
        this.g = Math.min(Math.max(DefinitionKt.NO_Float_VALUE, 0.6f), 1.0f);
        this.e = 0;
        this.i = hVar;
    }

    @Override // com.google.android.material.behavior.SwipeDismissBehavior, androidx.coordinatorlayout.widget.b
    public final boolean k(CoordinatorLayout coordinatorLayout, View view, MotionEvent motionEvent) {
        com.google.android.gms.auth.api.signin.internal.h hVar = this.i;
        hVar.getClass();
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked != 0) {
            if (actionMasked == 1 || actionMasked == 3) {
                com.quizlet.data.repository.achievements.h.c().i((e) hVar.b);
            }
        } else if (coordinatorLayout.p(view, (int) motionEvent.getX(), (int) motionEvent.getY())) {
            com.quizlet.data.repository.achievements.h.c().g((e) hVar.b);
        }
        return super.k(coordinatorLayout, view, motionEvent);
    }

    @Override // com.google.android.material.behavior.SwipeDismissBehavior
    public final boolean w(View view) {
        this.i.getClass();
        return view instanceof f;
    }
}
