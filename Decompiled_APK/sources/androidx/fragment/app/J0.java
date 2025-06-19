package androidx.fragment.app;

import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class J0 {
    public static final J0 a;
    public static final J0 b;
    public static final J0 c;
    public static final J0 d;
    public static final /* synthetic */ J0[] e;

    static {
        J0 j0 = new J0("REMOVED", 0);
        a = j0;
        J0 j02 = new J0("VISIBLE", 1);
        b = j02;
        J0 j03 = new J0("GONE", 2);
        c = j03;
        J0 j04 = new J0("INVISIBLE", 3);
        d = j04;
        e = new J0[]{j0, j02, j03, j04};
    }

    public static J0 valueOf(String str) {
        return (J0) Enum.valueOf(J0.class, str);
    }

    public static J0[] values() {
        return (J0[]) e.clone();
    }

    public final void a(View view, ViewGroup container) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(container, "container");
        AbstractC1136h0.N(2);
        int iOrdinal = ordinal();
        if (iOrdinal == 0) {
            ViewParent parent = view.getParent();
            ViewGroup viewGroup = parent instanceof ViewGroup ? (ViewGroup) parent : null;
            if (viewGroup != null) {
                if (AbstractC1136h0.N(2)) {
                    view.toString();
                    viewGroup.toString();
                }
                viewGroup.removeView(view);
                return;
            }
            return;
        }
        if (iOrdinal == 1) {
            if (AbstractC1136h0.N(2)) {
                Objects.toString(view);
            }
            ViewParent parent2 = view.getParent();
            if ((parent2 instanceof ViewGroup ? (ViewGroup) parent2 : null) == null) {
                if (AbstractC1136h0.N(2)) {
                    view.toString();
                    Objects.toString(container);
                }
                container.addView(view);
            }
            view.setVisibility(0);
            return;
        }
        if (iOrdinal == 2) {
            if (AbstractC1136h0.N(2)) {
                Objects.toString(view);
            }
            view.setVisibility(8);
        } else {
            if (iOrdinal != 3) {
                return;
            }
            if (AbstractC1136h0.N(2)) {
                Objects.toString(view);
            }
            view.setVisibility(4);
        }
    }
}
