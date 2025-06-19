package androidx.core.view;

import android.content.Context;
import android.graphics.Rect;
import android.view.TouchDelegate;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import com.google.android.material.bottomappbar.BottomAppBar;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.core.view.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC1068z implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ View b;

    public /* synthetic */ RunnableC1068z(View view, int i) {
        this.a = i;
        this.b = view;
    }

    @Override // java.lang.Runnable
    public final void run() {
        View view = this.b;
        switch (this.a) {
            case 0:
                ((InputMethodManager) view.getContext().getSystemService("input_method")).showSoftInput(view, 0);
                break;
            case 1:
                view.requestFocus();
                break;
            case 2:
                int i = BottomAppBar.E1;
                view.requestLayout();
                break;
            case 3:
                ((InputMethodManager) view.getContext().getSystemService(InputMethodManager.class)).showSoftInput(view, 1);
                break;
            default:
                Context context = view.getContext();
                if (context != null) {
                    Rect rect = new Rect();
                    view.getHitRect(rect);
                    float dimension = context.getResources().getDimension(R.dimen.quizlet_min_tap_target_size) - rect.height();
                    float dimension2 = context.getResources().getDimension(R.dimen.quizlet_min_tap_target_size) - rect.width();
                    float f = 2;
                    float f2 = dimension / f;
                    rect.top -= (int) Math.max(DefinitionKt.NO_Float_VALUE, f2);
                    rect.bottom += (int) Math.max(DefinitionKt.NO_Float_VALUE, f2);
                    float f3 = dimension2 / f;
                    rect.left -= (int) Math.max(DefinitionKt.NO_Float_VALUE, f3);
                    rect.right += (int) Math.max(DefinitionKt.NO_Float_VALUE, f3);
                    Object parent = view.getParent();
                    Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
                    ((View) parent).setTouchDelegate(new TouchDelegate(rect, view));
                    break;
                }
                break;
        }
    }
}
