package androidx.appcompat.view.menu;

import android.view.View;
import android.view.ViewTreeObserver;
import androidx.appcompat.widget.AppCompatSpinner;
import androidx.appcompat.widget.L0;
import androidx.appcompat.widget.O;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: androidx.appcompat.view.menu.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ViewTreeObserverOnGlobalLayoutListenerC0067d implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ ViewTreeObserverOnGlobalLayoutListenerC0067d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        switch (this.a) {
            case 0:
                h hVar = (h) this.b;
                if (hVar.a()) {
                    ArrayList arrayList = hVar.h;
                    if (arrayList.size() > 0 && !((g) arrayList.get(0)).a.y) {
                        View view = hVar.o;
                        if (view != null && view.isShown()) {
                            Iterator it2 = arrayList.iterator();
                            while (it2.hasNext()) {
                                ((g) it2.next()).a.f();
                            }
                            break;
                        } else {
                            hVar.dismiss();
                            break;
                        }
                    }
                }
                break;
            case 1:
                E e = (E) this.b;
                if (e.a()) {
                    L0 l0 = e.h;
                    if (!l0.y) {
                        View view2 = e.m;
                        if (view2 != null && view2.isShown()) {
                            l0.f();
                            break;
                        } else {
                            e.dismiss();
                            break;
                        }
                    }
                }
                break;
            case 2:
                AppCompatSpinner appCompatSpinner = (AppCompatSpinner) this.b;
                if (!appCompatSpinner.getInternalPopup().a()) {
                    appCompatSpinner.f.m(appCompatSpinner.getTextDirection(), appCompatSpinner.getTextAlignment());
                }
                ViewTreeObserver viewTreeObserver = appCompatSpinner.getViewTreeObserver();
                if (viewTreeObserver != null) {
                    viewTreeObserver.removeOnGlobalLayoutListener(this);
                    break;
                }
                break;
            default:
                O o = (O) this.b;
                AppCompatSpinner appCompatSpinner2 = o.G;
                o.getClass();
                if (!appCompatSpinner2.isAttachedToWindow() || !appCompatSpinner2.getGlobalVisibleRect(o.E)) {
                    o.dismiss();
                    break;
                } else {
                    o.s();
                    o.f();
                    break;
                }
                break;
        }
    }
}
