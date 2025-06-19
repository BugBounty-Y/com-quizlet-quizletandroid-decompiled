package androidx.core.splashscreen;

import android.graphics.Rect;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.window.SplashScreenView;
import androidx.appcompat.app.L;
import androidx.camera.camera2.internal.compat.quirk.c;
import androidx.camera.camera2.internal.m0;
import androidx.compose.ui.platform.H0;
import androidx.core.view.V;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.j;
import com.quizlet.quizletandroid.ui.RootActivity;
import java.util.HashMap;
import java.util.HashSet;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements ViewGroup.OnHierarchyChangeListener {
    public final /* synthetic */ int a = 0;
    public Object b;
    public final /* synthetic */ KeyEvent.Callback c;

    public a(b bVar, RootActivity rootActivity) {
        this.b = bVar;
        this.c = rootActivity;
    }

    private final void a(View view, View view2) {
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public final void onChildViewAdded(View view, View view2) {
        KeyEvent.Callback callback = this.c;
        switch (this.a) {
            case 0:
                if (c.D(view2)) {
                    SplashScreenView child = c.q(view2);
                    ((b) this.b).getClass();
                    Intrinsics.checkNotNullParameter(child, "child");
                    WindowInsets windowInsetsBuild = H0.d().build();
                    Intrinsics.checkNotNullExpressionValue(windowInsetsBuild, "Builder().build()");
                    Rect rect = new Rect(Integer.MIN_VALUE, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO);
                    if (windowInsetsBuild == child.getRootView().computeSystemWindowInsets(windowInsetsBuild, rect)) {
                        rect.isEmpty();
                    }
                    ((ViewGroup) ((RootActivity) callback).getWindow().getDecorView()).setOnHierarchyChangeListener(null);
                    break;
                }
                break;
            default:
                j jVar = (j) callback;
                if (view == jVar && (view2 instanceof Chip)) {
                    if (view2.getId() == -1) {
                        WeakHashMap weakHashMap = V.a;
                        view2.setId(View.generateViewId());
                    }
                    Chip chip = (Chip) view2;
                    m0 m0Var = jVar.h;
                    ((HashMap) m0Var.c).put(Integer.valueOf(chip.getId()), chip);
                    if (chip.isChecked()) {
                        m0Var.a(chip);
                    }
                    chip.setInternalOnCheckedChangeListener(new L(m0Var, 26));
                }
                ViewGroup.OnHierarchyChangeListener onHierarchyChangeListener = (ViewGroup.OnHierarchyChangeListener) this.b;
                if (onHierarchyChangeListener != null) {
                    onHierarchyChangeListener.onChildViewAdded(view, view2);
                    break;
                }
                break;
        }
    }

    @Override // android.view.ViewGroup.OnHierarchyChangeListener
    public final void onChildViewRemoved(View view, View view2) {
        switch (this.a) {
            case 0:
                break;
            default:
                j jVar = (j) this.c;
                if (view == jVar && (view2 instanceof Chip)) {
                    Chip chip = (Chip) view2;
                    m0 m0Var = jVar.h;
                    m0Var.getClass();
                    chip.setInternalOnCheckedChangeListener(null);
                    ((HashMap) m0Var.c).remove(Integer.valueOf(chip.getId()));
                    ((HashSet) m0Var.d).remove(Integer.valueOf(chip.getId()));
                }
                ViewGroup.OnHierarchyChangeListener onHierarchyChangeListener = (ViewGroup.OnHierarchyChangeListener) this.b;
                if (onHierarchyChangeListener != null) {
                    onHierarchyChangeListener.onChildViewRemoved(view, view2);
                    break;
                }
                break;
        }
    }

    public a(j jVar) {
        this.c = jVar;
    }
}
