package androidx.appcompat.view.menu;

import android.view.View;
import androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0;
import androidx.appcompat.widget.C0087h;
import androidx.appcompat.widget.C0089i;
import androidx.appcompat.widget.C0093k;
import androidx.appcompat.widget.C0095l;

/* renamed from: androidx.appcompat.view.menu.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0065b extends AbstractViewOnTouchListenerC0119x0 {
    public final /* synthetic */ int j = 0;
    public final /* synthetic */ View k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0065b(ActionMenuItemView actionMenuItemView) {
        super(actionMenuItemView);
        this.k = actionMenuItemView;
    }

    @Override // androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0
    public final D b() {
        C0087h c0087h;
        switch (this.j) {
            case 0:
                AbstractC0066c abstractC0066c = ((ActionMenuItemView) this.k).f;
                if (abstractC0066c == null || (c0087h = ((C0089i) abstractC0066c).a.t) == null) {
                    return null;
                }
                return c0087h.a();
            default:
                C0087h c0087h2 = ((C0093k) this.k).d.s;
                if (c0087h2 == null) {
                    return null;
                }
                return c0087h2.a();
        }
    }

    @Override // androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0
    public final boolean c() {
        D dB;
        switch (this.j) {
            case 0:
                ActionMenuItemView actionMenuItemView = (ActionMenuItemView) this.k;
                m mVar = actionMenuItemView.d;
                return mVar != null && mVar.a(actionMenuItemView.a) && (dB = b()) != null && dB.a();
            default:
                ((C0093k) this.k).d.l();
                return true;
        }
    }

    @Override // androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0
    public boolean d() {
        switch (this.j) {
            case 1:
                C0095l c0095l = ((C0093k) this.k).d;
                if (c0095l.u != null) {
                    return false;
                }
                c0095l.f();
                return true;
            default:
                return super.d();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0065b(C0093k c0093k, C0093k c0093k2) {
        super(c0093k2);
        this.k = c0093k;
    }
}
