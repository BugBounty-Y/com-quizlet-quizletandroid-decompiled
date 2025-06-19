package androidx.appcompat.view.menu;

import android.view.View;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import android.view.accessibility.AccessibilityManager;
import androidx.compose.ui.platform.AbstractC0930a;
import androidx.core.view.C1037a0;
import androidx.core.view.V;
import com.google.android.material.search.SearchBar;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.y0;

/* renamed from: androidx.appcompat.view.menu.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ViewOnAttachStateChangeListenerC0068e implements View.OnAttachStateChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ ViewOnAttachStateChangeListenerC0068e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a(View view) {
    }

    private final void b(View view) {
    }

    private final void c(View view) {
    }

    private final void d(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
        AccessibilityManager accessibilityManager;
        Object obj = this.b;
        switch (this.a) {
            case 0:
            case 1:
                break;
            case 2:
                androidx.compose.ui.platform.F f = (androidx.compose.ui.platform.F) obj;
                AccessibilityManager accessibilityManager2 = f.g;
                accessibilityManager2.addAccessibilityStateChangeListener(f.i);
                accessibilityManager2.addTouchExplorationStateChangeListener(f.j);
                break;
            case 3:
            case 4:
                break;
            case 5:
                SearchBar searchBar = (SearchBar) obj;
                searchBar.u1.addTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(searchBar.v1));
                break;
            default:
                com.google.android.material.textfield.l lVar = (com.google.android.material.textfield.l) obj;
                if (lVar.u != null && (accessibilityManager = lVar.t) != null) {
                    WeakHashMap weakHashMap = V.a;
                    if (lVar.isAttachedToWindow()) {
                        accessibilityManager.addTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(lVar.u));
                        break;
                    }
                }
                break;
        }
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        boolean z;
        AccessibilityManager accessibilityManager;
        switch (this.a) {
            case 0:
                h hVar = (h) this.b;
                ViewTreeObserver viewTreeObserver = hVar.x;
                if (viewTreeObserver != null) {
                    if (!viewTreeObserver.isAlive()) {
                        hVar.x = view.getViewTreeObserver();
                    }
                    hVar.x.removeGlobalOnLayoutListener(hVar.i);
                }
                view.removeOnAttachStateChangeListener(this);
                break;
            case 1:
                E e = (E) this.b;
                ViewTreeObserver viewTreeObserver2 = e.o;
                if (viewTreeObserver2 != null) {
                    if (!viewTreeObserver2.isAlive()) {
                        e.o = view.getViewTreeObserver();
                    }
                    e.o.removeGlobalOnLayoutListener(e.i);
                }
                view.removeOnAttachStateChangeListener(this);
                break;
            case 2:
                androidx.compose.ui.platform.F f = (androidx.compose.ui.platform.F) this.b;
                f.l.removeCallbacks(f.K);
                AccessibilityManager accessibilityManager2 = f.g;
                accessibilityManager2.removeAccessibilityStateChangeListener(f.i);
                accessibilityManager2.removeTouchExplorationStateChangeListener(f.j);
                break;
            case 3:
                AbstractC0930a abstractC0930a = (AbstractC0930a) this.b;
                Intrinsics.checkNotNullParameter(abstractC0930a, "<this>");
                Iterator it2 = kotlin.sequences.n.c(C1037a0.a, abstractC0930a.getParent()).iterator();
                while (true) {
                    if (it2.hasNext()) {
                        Object obj = (ViewParent) it2.next();
                        if (obj instanceof View) {
                            View view2 = (View) obj;
                            Intrinsics.checkNotNullParameter(view2, "<this>");
                            Object tag = view2.getTag(R.id.is_pooling_container_tag);
                            Boolean bool = tag instanceof Boolean ? (Boolean) tag : null;
                            if (bool != null ? bool.booleanValue() : false) {
                                z = true;
                            }
                        }
                    }
                }
                if (!z) {
                    abstractC0930a.disposeComposition();
                    break;
                }
                break;
            case 4:
                view.removeOnAttachStateChangeListener(this);
                ((y0) this.b).j(null);
                break;
            case 5:
                SearchBar searchBar = (SearchBar) this.b;
                searchBar.u1.removeTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(searchBar.v1));
                break;
            default:
                com.google.android.material.textfield.l lVar = (com.google.android.material.textfield.l) this.b;
                com.google.android.material.search.a aVar = lVar.u;
                if (aVar != null && (accessibilityManager = lVar.t) != null) {
                    accessibilityManager.removeTouchExplorationStateChangeListener(new androidx.core.view.accessibility.b(aVar));
                    break;
                }
                break;
        }
    }
}
