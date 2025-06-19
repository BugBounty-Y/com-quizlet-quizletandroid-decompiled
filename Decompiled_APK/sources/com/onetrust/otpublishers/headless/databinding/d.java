package com.onetrust.otpublishers.headless.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.BucketArcProgressBar;
import com.quizlet.quizletandroid.ui.common.views.SegmentedBucketLayout2;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;

/* loaded from: classes2.dex */
public final class d implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ViewGroup b;
    public final View c;
    public final View d;
    public final View e;
    public final View f;
    public final View g;
    public final Object h;

    public d(RelativeLayout relativeLayout, ImageView imageView, SwitchCompat switchCompat, TextView textView, View view, TextView textView2, RelativeLayout relativeLayout2) {
        this.a = 0;
        this.b = relativeLayout;
        this.d = imageView;
        this.e = switchCompat;
        this.f = textView;
        this.h = view;
        this.g = textView2;
        this.c = relativeLayout2;
    }

    public static d a(LayoutInflater layoutInflater, ViewGroup viewGroup) {
        View viewInflate = layoutInflater.inflate(R.layout.ot_google_vendor_list_item, viewGroup, false);
        int i = R.id.gv_show_more;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.gv_show_more, viewInflate);
        if (imageView != null) {
            i = R.id.switchButton;
            SwitchCompat switchCompat = (SwitchCompat) AbstractC3375o2.c(R.id.switchButton, viewInflate);
            if (switchCompat != null) {
                i = R.id.vendor_name;
                TextView textView = (TextView) AbstractC3375o2.c(R.id.vendor_name, viewInflate);
                if (textView != null) {
                    i = R.id.view3;
                    View viewC = AbstractC3375o2.c(R.id.view3, viewInflate);
                    if (viewC != null) {
                        i = R.id.view_powered_by_logo;
                        TextView textView2 = (TextView) AbstractC3375o2.c(R.id.view_powered_by_logo, viewInflate);
                        if (textView2 != null) {
                            i = R.id.vl_items;
                            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.vl_items, viewInflate);
                            if (relativeLayout != null) {
                                return new d((RelativeLayout) viewInflate, imageView, switchCompat, textView, viewC, textView2, relativeLayout);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return (ConstraintLayout) this.b;
    }

    public /* synthetic */ d(ConstraintLayout constraintLayout, ImageView imageView, QTextView qTextView, View view, QTextView qTextView2, View view2, Object obj, int i) {
        this.a = i;
        this.b = constraintLayout;
        this.d = imageView;
        this.c = qTextView;
        this.e = view;
        this.f = qTextView2;
        this.g = view2;
        this.h = obj;
    }

    public d(LinearLayout linearLayout, BucketArcProgressBar bucketArcProgressBar, RelativeLayout relativeLayout, QTextView qTextView, SegmentedBucketLayout2 segmentedBucketLayout2, AppCompatTextView appCompatTextView, QTextView qTextView2) {
        this.a = 1;
        this.c = linearLayout;
        this.d = bucketArcProgressBar;
        this.b = relativeLayout;
        this.e = qTextView;
        this.f = segmentedBucketLayout2;
        this.g = appCompatTextView;
        this.h = qTextView2;
    }

    public d(FrameLayout frameLayout, IconFontTextView iconFontTextView, ImageView imageView, FrameLayout frameLayout2, LinearLayout linearLayout, QRichFormField qRichFormField, IconFontTextView iconFontTextView2, LinearLayout linearLayout2, LinearLayout linearLayout3, QRichFormField qRichFormField2, LinearLayout linearLayout4) {
        this.a = 3;
        this.b = frameLayout;
        this.d = imageView;
        this.c = frameLayout2;
        this.e = qRichFormField;
        this.f = linearLayout2;
        this.g = linearLayout3;
        this.h = qRichFormField2;
    }

    public d(ScrollView scrollView, QTextView qTextView, QButton qButton, QButton qButton2, ImageView imageView, QTextView qTextView2, QTextView qTextView3) {
        this.a = 2;
        this.b = scrollView;
        this.c = qTextView;
        this.e = qButton;
        this.f = qButton2;
        this.d = imageView;
        this.g = qTextView2;
        this.h = qTextView3;
    }

    public d(ConstraintLayout constraintLayout, QTextView qTextView, QTextView qTextView2, View view, View view2, AssemblyPrimaryButton assemblyPrimaryButton, AssemblySecondaryButton assemblySecondaryButton) {
        this.a = 4;
        this.b = constraintLayout;
        this.c = qTextView;
        this.d = qTextView2;
        this.h = view;
        this.e = view2;
        this.f = assemblyPrimaryButton;
        this.g = assemblySecondaryButton;
    }
}
