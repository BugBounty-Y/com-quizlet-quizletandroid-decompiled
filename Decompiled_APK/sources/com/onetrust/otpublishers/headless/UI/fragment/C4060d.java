package com.onetrust.otpublishers.headless.UI.fragment;

import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4060d extends C4956o implements Function1 {
    public static final C4060d a = new C4060d(1, com.onetrust.otpublishers.headless.databinding.a.class, "bind", "bind(Landroid/view/View;)Lcom/onetrust/otpublishers/headless/databinding/FragmentOtBannerBinding;", 0);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        View p0 = (View) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        int i = R.id.alert_notice_text;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.alert_notice_text, p0);
        if (textView != null) {
            i = R.id.banner_additional_desc_after_desc;
            TextView textView2 = (TextView) AbstractC3375o2.c(R.id.banner_additional_desc_after_desc, p0);
            if (textView2 != null) {
                i = R.id.banner_additional_desc_after_dpd;
                TextView textView3 = (TextView) AbstractC3375o2.c(R.id.banner_additional_desc_after_dpd, p0);
                if (textView3 != null) {
                    i = R.id.banner_additional_desc_after_title;
                    TextView textView4 = (TextView) AbstractC3375o2.c(R.id.banner_additional_desc_after_title, p0);
                    if (textView4 != null) {
                        i = R.id.banner_IAB_desc;
                        TextView textView5 = (TextView) AbstractC3375o2.c(R.id.banner_IAB_desc, p0);
                        if (textView5 != null) {
                            i = R.id.banner_IAB_title;
                            TextView textView6 = (TextView) AbstractC3375o2.c(R.id.banner_IAB_title, p0);
                            if (textView6 != null) {
                                RelativeLayout relativeLayout = (RelativeLayout) p0;
                                i = R.id.banner_logo;
                                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.banner_logo, p0);
                                if (imageView != null) {
                                    i = R.id.banner_title;
                                    TextView textView7 = (TextView) AbstractC3375o2.c(R.id.banner_title, p0);
                                    if (textView7 != null) {
                                        i = R.id.banner_top_layout;
                                        LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.banner_top_layout, p0);
                                        if (linearLayout != null) {
                                            i = R.id.btn_accept_cookies;
                                            Button button = (Button) AbstractC3375o2.c(R.id.btn_accept_cookies, p0);
                                            if (button != null) {
                                                i = R.id.btn_reject_cookies;
                                                Button button2 = (Button) AbstractC3375o2.c(R.id.btn_reject_cookies, p0);
                                                if (button2 != null) {
                                                    i = R.id.button_layout;
                                                    LinearLayout linearLayout2 = (LinearLayout) AbstractC3375o2.c(R.id.button_layout, p0);
                                                    if (linearLayout2 != null) {
                                                        i = R.id.close_banner;
                                                        ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.close_banner, p0);
                                                        if (imageView2 != null) {
                                                            i = R.id.close_banner_button;
                                                            Button button3 = (Button) AbstractC3375o2.c(R.id.close_banner_button, p0);
                                                            if (button3 != null) {
                                                                i = R.id.close_banner_text;
                                                                TextView textView8 = (TextView) AbstractC3375o2.c(R.id.close_banner_text, p0);
                                                                if (textView8 != null) {
                                                                    i = R.id.cookie_policy_banner;
                                                                    TextView textView9 = (TextView) AbstractC3375o2.c(R.id.cookie_policy_banner, p0);
                                                                    if (textView9 != null) {
                                                                        i = R.id.cookies_setting;
                                                                        TextView textView10 = (TextView) AbstractC3375o2.c(R.id.cookies_setting, p0);
                                                                        if (textView10 != null) {
                                                                            i = R.id.cookies_setting_button;
                                                                            Button button4 = (Button) AbstractC3375o2.c(R.id.cookies_setting_button, p0);
                                                                            if (button4 != null) {
                                                                                i = R.id.cookies_text_layout;
                                                                                ScrollView scrollView = (ScrollView) AbstractC3375o2.c(R.id.cookies_text_layout, p0);
                                                                                if (scrollView != null) {
                                                                                    i = R.id.floating_button_layout;
                                                                                    if (((LinearLayout) AbstractC3375o2.c(R.id.floating_button_layout, p0)) != null) {
                                                                                        i = R.id.show_vendors_list;
                                                                                        TextView textView11 = (TextView) AbstractC3375o2.c(R.id.show_vendors_list, p0);
                                                                                        if (textView11 != null) {
                                                                                            i = R.id.small_banner_close;
                                                                                            ImageView imageView3 = (ImageView) AbstractC3375o2.c(R.id.small_banner_close, p0);
                                                                                            if (imageView3 != null) {
                                                                                                i = R.id.small_banner_title;
                                                                                                TextView textView12 = (TextView) AbstractC3375o2.c(R.id.small_banner_title, p0);
                                                                                                if (textView12 != null) {
                                                                                                    i = R.id.small_banner_top_layout;
                                                                                                    RelativeLayout relativeLayout2 = (RelativeLayout) AbstractC3375o2.c(R.id.small_banner_top_layout, p0);
                                                                                                    if (relativeLayout2 != null) {
                                                                                                        return new com.onetrust.otpublishers.headless.databinding.a(relativeLayout, textView, textView2, textView3, textView4, textView5, textView6, relativeLayout, imageView, textView7, linearLayout, button, button2, linearLayout2, imageView2, button3, textView8, textView9, textView10, button4, scrollView, textView11, imageView3, textView12, relativeLayout2);
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
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(p0.getResources().getResourceName(i)));
    }
}
