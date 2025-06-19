package com.quizlet.quizletandroid.ui.setcreation.callbacks;

import android.graphics.Canvas;
import androidx.core.util.c;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.I;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.quizletandroid.ui.setcreation.adapters.f;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes3.dex */
public final class b extends I {
    public float a;
    public f b;

    @Override // androidx.recyclerview.widget.I
    public final int getMovementFlags(RecyclerView recyclerView, F0 f0) {
        return I.makeMovementFlags(3, 48);
    }

    @Override // androidx.recyclerview.widget.I
    public final float getSwipeEscapeVelocity(float f) {
        return Float.MAX_VALUE;
    }

    @Override // androidx.recyclerview.widget.I
    public final float getSwipeThreshold(F0 f0) {
        return 1000.0f;
    }

    @Override // androidx.recyclerview.widget.I
    public final boolean isItemViewSwipeEnabled() {
        return true;
    }

    @Override // androidx.recyclerview.widget.I
    public final boolean isLongPressDragEnabled() {
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.recyclerview.widget.I
    public final void onChildDraw(Canvas canvas, RecyclerView recyclerView, F0 f0, float f, float f2, int i, boolean z) {
        if (f0 instanceof a) {
            a aVar = (a) f0;
            if (i == 2) {
                super.onChildDraw(canvas, recyclerView, f0, f, f2, i, z);
                aVar.getClass();
                return;
            }
            if (i != 1) {
                super.onChildDraw(canvas, recyclerView, f0, f, f2, i, z);
                aVar.getClass();
                return;
            }
            f fVar = this.b;
            if (z) {
                float fFloatValue = this.a - f;
                int adapterPosition = f0.getAdapterPosition();
                c cVar = fVar.g;
                if (cVar != null) {
                    if (((Integer) cVar.a).intValue() != adapterPosition) {
                        fVar.notifyItemChanged(((Integer) fVar.g.a).intValue(), 100);
                    } else {
                        fFloatValue += ((Float) fVar.g.b).floatValue();
                    }
                }
                fVar.g = new c(Integer.valueOf(adapterPosition), Float.valueOf(fFloatValue));
                fVar.notifyItemChanged(adapterPosition, 100);
                this.a = f;
                return;
            }
            float f3 = this.a;
            if (f3 != DefinitionKt.NO_Float_VALUE) {
                float fFloatValue2 = f3 - f;
                int adapterPosition2 = f0.getAdapterPosition();
                c cVar2 = fVar.g;
                if (cVar2 != null) {
                    fFloatValue2 += ((Float) cVar2.b).floatValue();
                    if (((Integer) fVar.g.a).intValue() != adapterPosition2) {
                        fVar.notifyItemChanged(((Integer) fVar.g.a).intValue(), 100);
                    }
                }
                fVar.g = new c(Integer.valueOf(adapterPosition2), Float.valueOf(fFloatValue2));
                fVar.notifyItemChanged(adapterPosition2, 200);
                this.a = DefinitionKt.NO_Float_VALUE;
            }
        }
    }

    @Override // androidx.recyclerview.widget.I
    public final boolean onMove(RecyclerView recyclerView, F0 f0, F0 f02) {
        f0.getAdapterPosition();
        f02.getAdapterPosition();
        this.b.getClass();
        return true;
    }

    @Override // androidx.recyclerview.widget.I
    public final void onSwiped(F0 f0, int i) {
        timber.log.c.b(new IllegalStateException("Callback reports a successful swipe. This should not be possible"));
    }
}
