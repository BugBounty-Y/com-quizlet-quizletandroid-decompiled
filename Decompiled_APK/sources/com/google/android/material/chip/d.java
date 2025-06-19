package com.google.android.material.chip;

import android.graphics.Rect;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityNodeInfo;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class d extends androidx.customview.widget.a {
    public final /* synthetic */ Chip q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Chip chip, Chip chip2) {
        super(chip2);
        this.q = chip;
    }

    @Override // androidx.customview.widget.a
    public final void l(ArrayList arrayList) {
        f fVar;
        arrayList.add(0);
        Rect rect = Chip.x;
        Chip chip = this.q;
        if (!chip.c() || (fVar = chip.e) == null || !fVar.L || chip.h == null) {
            return;
        }
        arrayList.add(1);
    }

    @Override // androidx.customview.widget.a
    public final void o(int i, androidx.core.view.accessibility.e eVar) {
        AccessibilityNodeInfo accessibilityNodeInfo = eVar.a;
        if (i != 1) {
            accessibilityNodeInfo.setContentDescription("");
            accessibilityNodeInfo.setBoundsInParent(Chip.x);
            return;
        }
        Chip chip = this.q;
        CharSequence closeIconContentDescription = chip.getCloseIconContentDescription();
        if (closeIconContentDescription != null) {
            accessibilityNodeInfo.setContentDescription(closeIconContentDescription);
        } else {
            CharSequence text = chip.getText();
            accessibilityNodeInfo.setContentDescription(chip.getContext().getString(R.string.mtrl_chip_close_icon_content_description, TextUtils.isEmpty(text) ? "" : text).trim());
        }
        accessibilityNodeInfo.setBoundsInParent(chip.getCloseIconTouchBoundsInt());
        eVar.b(androidx.core.view.accessibility.d.e);
        accessibilityNodeInfo.setEnabled(chip.isEnabled());
    }
}
