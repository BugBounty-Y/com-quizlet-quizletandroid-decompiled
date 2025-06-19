package com.onetrust.otpublishers.headless.UI.fragment;

import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.cardview.widget.CardView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class B extends C4956o implements Function1 {
    public static final B a = new B(1, com.onetrust.otpublishers.headless.databinding.c.class, "bind", "bind(Landroid/view/View;)Lcom/onetrust/otpublishers/headless/databinding/FragmentOtVendorsListBinding;", 0);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        View p0 = (View) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        View viewC = AbstractC3375o2.c(R.id.main_layout, p0);
        if (viewC == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(p0.getResources().getResourceName(R.id.main_layout)));
        }
        int i = R.id.VL_page_title;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.VL_page_title, viewC);
        if (textView != null) {
            i = R.id.all_consent_toggle;
            SwitchCompat switchCompat = (SwitchCompat) AbstractC3375o2.c(R.id.all_consent_toggle, viewC);
            if (switchCompat != null) {
                i = R.id.all_leg_int_toggle;
                if (((SwitchCompat) AbstractC3375o2.c(R.id.all_leg_int_toggle, viewC)) != null) {
                    i = R.id.allow_all_layout;
                    if (((LinearLayout) AbstractC3375o2.c(R.id.allow_all_layout, viewC)) != null) {
                        i = R.id.allow_all_toggle;
                        if (((SwitchCompat) AbstractC3375o2.c(R.id.allow_all_toggle, viewC)) != null) {
                            i = R.id.back_from_vendorlist;
                            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.back_from_vendorlist, viewC);
                            if (imageView != null) {
                                i = R.id.button_general_vendors;
                                AppCompatButton appCompatButton = (AppCompatButton) AbstractC3375o2.c(R.id.button_general_vendors, viewC);
                                if (appCompatButton != null) {
                                    i = R.id.button_google_vendors;
                                    AppCompatButton appCompatButton2 = (AppCompatButton) AbstractC3375o2.c(R.id.button_google_vendors, viewC);
                                    if (appCompatButton2 != null) {
                                        i = R.id.button_iab_vendors;
                                        AppCompatButton appCompatButton3 = (AppCompatButton) AbstractC3375o2.c(R.id.button_iab_vendors, viewC);
                                        if (appCompatButton3 != null) {
                                            i = R.id.consent_text;
                                            if (((TextView) AbstractC3375o2.c(R.id.consent_text, viewC)) != null) {
                                                i = R.id.filter_vendors;
                                                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.filter_vendors, viewC);
                                                if (imageView2 != null) {
                                                    i = R.id.footer_layout;
                                                    RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.footer_layout, viewC);
                                                    if (relativeLayout != null) {
                                                        i = R.id.leg_int_text;
                                                        if (((TextView) AbstractC3375o2.c(R.id.leg_int_text, viewC)) != null) {
                                                            i = R.id.rv_vendors_list;
                                                            RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.rv_vendors_list, viewC);
                                                            if (recyclerView != null) {
                                                                i = R.id.search_bar_layout;
                                                                if (((LinearLayout) AbstractC3375o2.c(R.id.search_bar_layout, viewC)) != null) {
                                                                    i = R.id.search_vendor;
                                                                    SearchView searchView = (SearchView) AbstractC3375o2.c(R.id.search_vendor, viewC);
                                                                    if (searchView != null) {
                                                                        i = R.id.tab_layout;
                                                                        CardView cardView = (CardView) AbstractC3375o2.c(R.id.tab_layout, viewC);
                                                                        if (cardView != null) {
                                                                            i = R.id.vendor_allow_all_title;
                                                                            TextView textView2 = (TextView) AbstractC3375o2.c(R.id.vendor_allow_all_title, viewC);
                                                                            if (textView2 != null) {
                                                                                i = R.id.vendors_confirm_choices_btn;
                                                                                Button button = (Button) AbstractC3375o2.c(R.id.vendors_confirm_choices_btn, viewC);
                                                                                if (button != null) {
                                                                                    RelativeLayout relativeLayout2 = (RelativeLayout) viewC;
                                                                                    i = R.id.view2;
                                                                                    if (AbstractC3375o2.c(R.id.view2, viewC) != null) {
                                                                                        i = R.id.view3;
                                                                                        View viewC2 = AbstractC3375o2.c(R.id.view3, viewC);
                                                                                        if (viewC2 != null) {
                                                                                            return new com.onetrust.otpublishers.headless.databinding.c((CoordinatorLayout) p0, new com.onetrust.otpublishers.headless.databinding.g(relativeLayout2, textView, switchCompat, imageView, appCompatButton, appCompatButton2, appCompatButton3, imageView2, relativeLayout, recyclerView, searchView, cardView, textView2, button, relativeLayout2, viewC2));
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i)));
    }
}
