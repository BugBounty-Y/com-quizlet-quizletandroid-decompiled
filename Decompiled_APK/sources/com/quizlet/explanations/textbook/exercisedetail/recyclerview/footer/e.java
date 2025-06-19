package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import android.content.Context;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.explanations.databinding.r;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class e extends com.quizlet.baserecyclerview.c {
    public final u d;
    public final u e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        final int i = 0;
        this.d = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.d
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        AssemblySecondaryButton firstExerciseButton = ((r) this.b.e()).b;
                        Intrinsics.checkNotNullExpressionValue(firstExerciseButton, "firstExerciseButton");
                        return firstExerciseButton;
                    default:
                        AssemblySecondaryButton secondExerciseButton = ((r) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(secondExerciseButton, "secondExerciseButton");
                        return secondExerciseButton;
                }
            }
        });
        final int i2 = 1;
        this.e = l.b(new Function0(this) { // from class: com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.d
            public final /* synthetic */ e b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        AssemblySecondaryButton firstExerciseButton = ((r) this.b.e()).b;
                        Intrinsics.checkNotNullExpressionValue(firstExerciseButton, "firstExerciseButton");
                        return firstExerciseButton;
                    default:
                        AssemblySecondaryButton secondExerciseButton = ((r) this.b.e()).c;
                        Intrinsics.checkNotNullExpressionValue(secondExerciseButton, "secondExerciseButton");
                        return secondExerciseButton;
                }
            }
        });
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        int i = R.id.firstExerciseButton;
        AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.firstExerciseButton, view);
        if (assemblySecondaryButton != null) {
            i = R.id.secondExerciseButton;
            AssemblySecondaryButton assemblySecondaryButton2 = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.secondExerciseButton, view);
            if (assemblySecondaryButton2 != null) {
                r rVar = new r((ConstraintLayout) view, assemblySecondaryButton, assemblySecondaryButton2);
                Intrinsics.checkNotNullExpressionValue(rVar, "bind(...)");
                return rVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(h item) {
        int i;
        Intrinsics.checkNotNullParameter(item, "item");
        g((AssemblySecondaryButton) this.d.getValue(), item.a);
        u uVar = this.e;
        AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) uVar.getValue();
        b bVar = item.b;
        if (bVar != null) {
            g((AssemblySecondaryButton) uVar.getValue(), bVar);
            i = 0;
        } else {
            i = 8;
        }
        assemblySecondaryButton.setVisibility(i);
    }

    public final void g(AssemblySecondaryButton assemblySecondaryButton, b bVar) {
        com.quizlet.qutils.string.f fVar = bVar.d;
        Context context = this.b;
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        fVar.getClass();
        assemblySecondaryButton.setText(AbstractC3053s1.e(fVar, context));
        if (bVar.a != null) {
            assemblySecondaryButton.setOnClickListener(new com.braze.ui.inappmessage.d(bVar, 24));
        }
    }
}
