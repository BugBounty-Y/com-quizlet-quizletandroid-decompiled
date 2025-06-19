package androidx.viewpager.widget;

import android.os.Bundle;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.core.view.C1038b;
import androidx.webkit.internal.p;
import com.google.android.material.bottomsheet.h;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.button.MaterialButtonToggleGroup;
import com.google.android.material.datepicker.k;
import com.google.android.material.internal.CheckableImageButton;
import com.google.android.material.internal.NavigationMenuItemView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public final class e extends C1038b {
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    public /* synthetic */ e(Object obj, int i) {
        this.d = i;
        this.e = obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0032  */
    @Override // androidx.core.view.C1038b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c(android.view.View r3, android.view.accessibility.AccessibilityEvent r4) {
        /*
            r2 = this;
            int r0 = r2.d
            switch(r0) {
                case 0: goto L16;
                case 4: goto L9;
                default: goto L5;
            }
        L5:
            super.c(r3, r4)
            return
        L9:
            super.c(r3, r4)
            java.lang.Object r3 = r2.e
            com.google.android.material.internal.CheckableImageButton r3 = (com.google.android.material.internal.CheckableImageButton) r3
            boolean r3 = r3.d
            r4.setChecked(r3)
            return
        L16:
            super.c(r3, r4)
            java.lang.Class<androidx.viewpager.widget.ViewPager> r3 = androidx.viewpager.widget.ViewPager.class
            java.lang.String r3 = r3.getName()
            r4.setClassName(r3)
            java.lang.Object r3 = r2.e
            androidx.viewpager.widget.ViewPager r3 = (androidx.viewpager.widget.ViewPager) r3
            androidx.viewpager.widget.a r0 = r3.e
            if (r0 == 0) goto L32
            int r0 = r0.c()
            r1 = 1
            if (r0 <= r1) goto L32
            goto L33
        L32:
            r1 = 0
        L33:
            r4.setScrollable(r1)
            int r0 = r4.getEventType()
            r1 = 4096(0x1000, float:5.74E-42)
            if (r0 != r1) goto L53
            androidx.viewpager.widget.a r0 = r3.e
            if (r0 == 0) goto L53
            int r0 = r0.c()
            r4.setItemCount(r0)
            int r0 = r3.f
            r4.setFromIndex(r0)
            int r3 = r3.f
            r4.setToIndex(r3)
        L53:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.e.c(android.view.View, android.view.accessibility.AccessibilityEvent):void");
    }

    @Override // androidx.core.view.C1038b
    public final void d(View view, androidx.core.view.accessibility.e eVar) {
        int i = -1;
        boolean z = false;
        Object obj = this.e;
        View.AccessibilityDelegate accessibilityDelegate = this.a;
        switch (this.d) {
            case 0:
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, eVar.a);
                eVar.i(ViewPager.class.getName());
                ViewPager viewPager = (ViewPager) obj;
                a aVar = viewPager.e;
                if (aVar != null && aVar.c() > 1) {
                    z = true;
                }
                eVar.l(z);
                if (viewPager.canScrollHorizontally(1)) {
                    eVar.a(4096);
                }
                if (viewPager.canScrollHorizontally(-1)) {
                    eVar.a(8192);
                    break;
                }
                break;
            case 1:
                AccessibilityNodeInfo accessibilityNodeInfo = eVar.a;
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo);
                if (!((h) obj).j) {
                    accessibilityNodeInfo.setDismissable(false);
                    break;
                } else {
                    eVar.a(1048576);
                    accessibilityNodeInfo.setDismissable(true);
                    break;
                }
            case 2:
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, eVar.a);
                int i2 = MaterialButtonToggleGroup.k;
                MaterialButtonToggleGroup materialButtonToggleGroup = (MaterialButtonToggleGroup) obj;
                if (view instanceof MaterialButton) {
                    int i3 = 0;
                    int i4 = 0;
                    while (true) {
                        if (i3 < materialButtonToggleGroup.getChildCount()) {
                            if (materialButtonToggleGroup.getChildAt(i3) == view) {
                                i = i4;
                            } else {
                                if ((materialButtonToggleGroup.getChildAt(i3) instanceof MaterialButton) && materialButtonToggleGroup.c(i3)) {
                                    i4++;
                                }
                                i3++;
                            }
                        }
                    }
                }
                eVar.k(p.r(0, 1, i, 1, ((MaterialButton) view).o));
                break;
            case 3:
                AccessibilityNodeInfo accessibilityNodeInfo2 = eVar.a;
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo2);
                k kVar = (k) obj;
                accessibilityNodeInfo2.setHintText(kVar.l.getVisibility() == 0 ? kVar.getString(R.string.mtrl_picker_toggle_to_year_selection) : kVar.getString(R.string.mtrl_picker_toggle_to_day_selection));
                break;
            case 4:
                AccessibilityNodeInfo accessibilityNodeInfo3 = eVar.a;
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo3);
                CheckableImageButton checkableImageButton = (CheckableImageButton) obj;
                accessibilityNodeInfo3.setCheckable(checkableImageButton.e);
                accessibilityNodeInfo3.setChecked(checkableImageButton.d);
                break;
            case 5:
                AccessibilityNodeInfo accessibilityNodeInfo4 = eVar.a;
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo4);
                accessibilityNodeInfo4.setCheckable(((NavigationMenuItemView) obj).x);
                break;
            default:
                AccessibilityNodeInfo accessibilityNodeInfo5 = eVar.a;
                accessibilityDelegate.onInitializeAccessibilityNodeInfo(view, accessibilityNodeInfo5);
                eVar.a(1048576);
                accessibilityNodeInfo5.setDismissable(true);
                break;
        }
    }

    @Override // androidx.core.view.C1038b
    public boolean g(View view, int i, Bundle bundle) {
        switch (this.d) {
            case 0:
                if (!super.g(view, i, bundle)) {
                    ViewPager viewPager = (ViewPager) this.e;
                    if (i == 4096) {
                        if (viewPager.canScrollHorizontally(1)) {
                            viewPager.setCurrentItem(viewPager.f + 1);
                            break;
                        }
                    } else if (i == 8192 && viewPager.canScrollHorizontally(-1)) {
                        viewPager.setCurrentItem(viewPager.f - 1);
                        break;
                    }
                    break;
                }
                break;
            case 1:
                if (i == 1048576) {
                    h hVar = (h) this.e;
                    if (hVar.j) {
                        hVar.cancel();
                        break;
                    }
                }
                break;
            case 6:
                if (i != 1048576) {
                    break;
                } else {
                    ((com.google.android.material.snackbar.h) ((com.google.android.material.snackbar.g) this.e)).a(3);
                    break;
                }
        }
        return super.g(view, i, bundle);
    }
}
