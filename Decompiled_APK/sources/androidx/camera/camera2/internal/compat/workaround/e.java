package androidx.camera.camera2.internal.compat.workaround;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.hardware.camera2.CaptureRequest;
import android.os.Bundle;
import android.text.method.PasswordTransformationMethod;
import android.util.TypedValue;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.camera.camera2.internal.compat.quirk.Preview3AThreadCrashQuirk;
import androidx.camera.camera2.internal.compat.quirk.StillCaptureFlashStopRepeatingQuirk;
import androidx.camera.camera2.internal.compat.quirk.TorchIsClosedAfterImageCapturingQuirk;
import androidx.camera.core.a0;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.F;
import androidx.camera.core.impl.J;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.i0;
import androidx.camera.core.internal.compat.quirk.SurfaceOrderQuirk;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.motion.widget.n;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import coil3.size.h;
import com.google.android.gms.internal.ads.Q1;
import com.google.android.gms.internal.ads.Uh;
import com.google.android.gms.internal.ads.Xh;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e implements coil3.util.d, Xh, com.quizlet.uicommon.ui.common.widgets.e {
    public final /* synthetic */ int a;
    public boolean b;

    public /* synthetic */ e(int i, boolean z) {
        this.a = i;
    }

    public static void d(Button button, JSONObject jSONObject) {
        JSONObject jSONObjectJ = retrofit2.adapter.rxjava3.d.j("button", jSONObject);
        if (retrofit2.adapter.rxjava3.d.o(jSONObjectJ) || !jSONObjectJ.optBoolean("show")) {
            return;
        }
        button.setVisibility(0);
        button.setText(jSONObjectJ.optString("text"));
        button.setTextColor(Color.parseColor(jSONObjectJ.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR)));
        if (jSONObjectJ.optBoolean("showAsLink")) {
            button.setBackgroundColor(Color.parseColor("#00000000"));
            button.setPaintFlags(button.getPaintFlags() | 8);
            return;
        }
        n nVar = new n();
        String strOptString = jSONObjectJ.optString(OTUXParamsKeys.OT_UX_BORDER_COLOR);
        String strOptString2 = jSONObjectJ.optString("color");
        nVar.g = strOptString;
        nVar.i = jSONObjectJ.optString(OTUXParamsKeys.OT_UX_BORDER_RADIUS);
        nVar.h = "2";
        assistantMode.utils.studiableMetadata.b.q(button.getContext(), button, nVar, strOptString2, strOptString);
    }

    public static void e(CardView cardView, CardView cardView2, TextView textView, TextView textView2, Button button, ImageView imageView, ImageView imageView2, JSONObject jSONObject) {
        JSONObject jSONObjectJ = retrofit2.adapter.rxjava3.d.j("title", jSONObject);
        if (jSONObjectJ != null) {
            textView.setText(jSONObjectJ.optString("text"));
            String strOptString = jSONObjectJ.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                textView.setTextColor(Color.parseColor(strOptString));
            }
        }
        JSONObject jSONObjectJ2 = retrofit2.adapter.rxjava3.d.j(OTUXParamsKeys.OT_UX_DESCRIPTION, jSONObject);
        if (jSONObjectJ2 != null) {
            textView2.setText(jSONObjectJ2.optString("text"));
            String strOptString2 = jSONObjectJ2.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                textView2.setTextColor(Color.parseColor(strOptString2));
            }
        }
        JSONObject jSONObjectJ3 = retrofit2.adapter.rxjava3.d.j(OTVendorListMode.GENERAL, jSONObject);
        if (!retrofit2.adapter.rxjava3.d.o(jSONObjectJ3)) {
            Drawable drawable = imageView.getDrawable();
            String strOptString3 = jSONObjectJ != null ? jSONObjectJ.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR) : null;
            boolean zOptBoolean = jSONObjectJ3.optBoolean("showClose");
            if (drawable != null && !com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                drawable.setTint(Color.parseColor(strOptString3));
            }
            imageView.setVisibility(zOptBoolean ? 0 : 8);
            Drawable background = imageView2.getBackground();
            String strOptString4 = jSONObjectJ3.optString("iconBackgroundColor");
            boolean zOptBoolean2 = jSONObjectJ3.optBoolean("showIcon");
            if (background != null && !com.onetrust.otpublishers.headless.Internal.a.j(strOptString4)) {
                background.setTint(Color.parseColor(strOptString4));
            }
            imageView2.setVisibility(zOptBoolean2 ? 0 : 8);
            String strOptString5 = jSONObjectJ3.optString(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR);
            String strOptString6 = jSONObjectJ3.optString(OTUXParamsKeys.OT_UX_BORDER_COLOR);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString5)) {
                cardView2.setBackgroundColor(Color.parseColor(strOptString5));
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString6)) {
                cardView.setBackgroundColor(Color.parseColor(strOptString6));
            }
        }
        d(button, jSONObject);
    }

    public static void h(CardView cardView, CardView cardView2, TextView textView, TextView textView2, Button button, ImageView imageView, ImageView imageView2, JSONObject jSONObject, OTConfiguration oTConfiguration) {
        int iD = assistantMode.utils.studiableMetadata.b.d(textView.getContext(), oTConfiguration);
        String str = iD == 22 ? OTUXParamsKeys.OT_UX_TEXT_COLOR : "textColorDark";
        JSONObject jSONObjectJ = retrofit2.adapter.rxjava3.d.j("title", jSONObject);
        if (jSONObjectJ != null) {
            textView.setText(jSONObjectJ.optString("text"));
            String strOptString = jSONObjectJ.optString(str);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                textView.setTextColor(Color.parseColor(strOptString));
            }
        }
        JSONObject jSONObjectJ2 = retrofit2.adapter.rxjava3.d.j(OTUXParamsKeys.OT_UX_DESCRIPTION, jSONObject);
        if (jSONObjectJ2 != null) {
            textView2.setText(jSONObjectJ2.optString("text"));
            String strOptString2 = jSONObjectJ2.optString(str);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                textView2.setTextColor(Color.parseColor(strOptString2));
            }
        }
        JSONObject jSONObjectJ3 = retrofit2.adapter.rxjava3.d.j(OTVendorListMode.GENERAL, jSONObject);
        String str2 = iD == 22 ? OTUXParamsKeys.OT_UX_BORDER_COLOR : "borderColorDark";
        if (!retrofit2.adapter.rxjava3.d.o(jSONObjectJ3)) {
            Drawable drawable = imageView.getDrawable();
            String strOptString3 = jSONObjectJ != null ? jSONObjectJ.optString(str) : null;
            boolean zOptBoolean = jSONObjectJ3.optBoolean("showClose");
            if (drawable != null && !com.onetrust.otpublishers.headless.Internal.a.j(strOptString3)) {
                drawable.setTint(Color.parseColor(strOptString3));
            }
            imageView.setVisibility(zOptBoolean ? 0 : 8);
            String str3 = iD == 22 ? "iconBackgroundColor" : "iconBackgroundColorDark";
            Drawable background = imageView2.getBackground();
            String strOptString4 = jSONObjectJ3.optString(str3);
            boolean zOptBoolean2 = jSONObjectJ3.optBoolean("showIcon");
            if (background != null && !com.onetrust.otpublishers.headless.Internal.a.j(strOptString4)) {
                background.setTint(Color.parseColor(strOptString4));
            }
            imageView2.setVisibility(zOptBoolean2 ? 0 : 8);
            String strOptString5 = jSONObjectJ3.optString(iD == 22 ? OTUXParamsKeys.OT_UX_BACKGROUND_COLOR : "backgroundColorDark");
            String strOptString6 = jSONObjectJ3.optString(str2);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString5)) {
                cardView2.setBackgroundColor(Color.parseColor(strOptString5));
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString6)) {
                cardView.setBackgroundColor(Color.parseColor(strOptString6));
            }
        }
        JSONObject jSONObjectJ4 = retrofit2.adapter.rxjava3.d.j("button", jSONObject);
        if (retrofit2.adapter.rxjava3.d.o(jSONObjectJ4) || !jSONObjectJ4.optBoolean("show")) {
            return;
        }
        button.setVisibility(0);
        button.setText(jSONObjectJ4.optString("text"));
        button.setTextColor(Color.parseColor(jSONObjectJ4.optString(str)));
        if (jSONObjectJ4.optBoolean("showAsLink")) {
            button.setBackgroundColor(Color.parseColor("#00000000"));
            button.setPaintFlags(button.getPaintFlags() | 8);
            return;
        }
        String strOptString7 = jSONObjectJ4.optString(str2);
        String strOptString8 = jSONObjectJ4.optString(iD == 22 ? "color" : "colorDark");
        String strOptString9 = jSONObjectJ4.optString(OTUXParamsKeys.OT_UX_BORDER_RADIUS);
        Context context = button.getContext();
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString8)) {
            OTLogger.c("UIUtils", 3, "Button set background color called with empty buttonBackGroundColor.");
            return;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            button.setBackgroundColor(Color.parseColor(strOptString8));
            return;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j("2") && com.onetrust.otpublishers.headless.Internal.a.j(strOptString9)) {
            assistantMode.utils.studiableMetadata.b.v(button, strOptString8, strOptString7);
            return;
        }
        String str4 = com.onetrust.otpublishers.headless.Internal.a.j("2") ? "4" : "2";
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString7)) {
            strOptString7 = strOptString8;
        }
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setStroke(Integer.parseInt(str4), Color.parseColor(strOptString7));
        gradientDrawable.setColor(Color.parseColor(strOptString8));
        if (!com.onetrust.otpublishers.headless.Internal.a.j(strOptString9)) {
            gradientDrawable.setCornerRadius(TypedValue.applyDimension(1, Integer.parseInt(strOptString9), context.getResources().getDisplayMetrics()));
        }
        button.setBackground(gradientDrawable);
    }

    public static void i(Q1 q1, ImageView imageView) {
        JSONObject jSONObjectJ = retrofit2.adapter.rxjava3.d.j("button", (JSONObject) q1.e);
        if (jSONObjectJ != null) {
            String strOptString = jSONObjectJ.optString("color");
            String strOptString2 = jSONObjectJ.optString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
            imageView.getBackground().setTint(Color.parseColor(strOptString));
            imageView.getDrawable().setTint(Color.parseColor(strOptString2));
        }
    }

    public static F k(F f) {
        a0 a0Var = new a0();
        a0Var.a = f.c;
        Iterator it2 = Collections.unmodifiableList(f.a).iterator();
        while (it2.hasNext()) {
            ((HashSet) a0Var.c).add((J) it2.next());
        }
        a0Var.d(f.b);
        X xB = X.b();
        xB.m(androidx.camera.camera2.impl.b.U(CaptureRequest.FLASH_MODE), 0);
        a0Var.d(new androidx.camera.camera2.impl.b(C0163c0.a(xB), 4));
        return a0Var.e();
    }

    public static void l(e eVar, BaseFragment fragment, int i, String[] permissions, int[] grantResults, Function0 permissionGranted, Function0 permissionPermanentlyDenied) {
        com.quizlet.login.resetpassword.ui.a permissionDenied = new com.quizlet.login.resetpassword.ui.a(20);
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        Intrinsics.checkNotNullParameter(permissionGranted, "permissionGranted");
        Intrinsics.checkNotNullParameter(permissionPermanentlyDenied, "permissionPermanentlyDenied");
        Intrinsics.checkNotNullParameter(permissionDenied, "permissionDenied");
        if (i == 101) {
            int length = grantResults.length;
            for (int i2 = 0; i2 < length; i2++) {
                String str = permissions[i2];
                int i3 = grantResults[i2];
                if (i3 != -1) {
                    if (i3 == 0) {
                        permissionGranted.invoke();
                    }
                } else if (fragment.shouldShowRequestPermissionRationale(str) || eVar.b) {
                    Unit unit = Unit.a;
                } else {
                    permissionPermanentlyDenied.invoke();
                }
            }
        }
    }

    public static void r(Fragment fragment) {
        AbstractC1136h0 supportFragmentManager;
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        com.quizlet.quizletandroid.ui.permissions.c cVar = new com.quizlet.quizletandroid.ui.permissions.c();
        Bundle bundle = new Bundle();
        bundle.putInt("arg_title_resid", R.string.permission_from_settings_dialog_title);
        bundle.putInt("arg_message_resid", R.string.permission_from_settings_dialog_message);
        bundle.putInt("arg_confirm_resid", R.string.permission_from_settings_positive_dialog_button);
        bundle.putInt("arg_cancel_resid", R.string.permission_from_settings_negative_dialog_button);
        cVar.setArguments(bundle);
        I activity = fragment.getActivity();
        if (activity == null || (supportFragmentManager = activity.getSupportFragmentManager()) == null) {
            return;
        }
        cVar.O(supportFragmentManager, "PermissionFromSettingsDialog");
    }

    @Override // coil3.util.d
    public boolean a(h hVar) {
        return this.b;
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        Uh uh = (Uh) obj;
        switch (this.a) {
            case 6:
                uh.o(this.b);
                break;
            default:
                uh.S(this.b);
                break;
        }
    }

    @Override // coil3.util.d
    public boolean c() {
        return this.b;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public boolean f(QFormField qFormField) {
        return true;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public CharSequence g(Context context) {
        return context.getString(this.b ? R.string.signup_password_hide : R.string.signup_password_show);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void j(QFormField qFormField) {
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void m(QFormField qFormField, StatefulTintImageView statefulTintImageView) {
        this.b = !this.b;
        statefulTintImageView.setImageResource(n());
        statefulTintImageView.setContentDescription(g(statefulTintImageView.getContext()));
        EditText editText = qFormField.getEditText();
        int selectionStart = editText.getSelectionStart();
        int selectionEnd = editText.getSelectionEnd();
        editText.setTransformationMethod(this.b ? null : new PasswordTransformationMethod());
        qFormField.getEditText().setSelection(selectionStart, selectionEnd);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public int n() {
        return this.b ? R.drawable.ic_sys_eye_closed : R.drawable.ic_sys_eye;
    }

    public boolean o(ArrayList arrayList, boolean z) {
        if (!this.b || !z) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Integer num = (Integer) ((CaptureRequest) it2.next()).get(CaptureRequest.FLASH_MODE);
            if (num != null && num.intValue() == 2) {
                return true;
            }
        }
        return false;
    }

    public void p(BaseFragment fragment) {
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Intrinsics.checkNotNullParameter("android.permission.CAMERA", "permission");
        this.b = fragment.shouldShowRequestPermissionRationale("android.permission.CAMERA");
        fragment.requestPermissions(new String[]{"android.permission.CAMERA"}, 101);
    }

    public boolean q(ArrayList arrayList, boolean z) {
        if (!this.b || !z) {
            return false;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            int iIntValue = ((Integer) ((CaptureRequest) it2.next()).get(CaptureRequest.CONTROL_AE_MODE)).intValue();
            if (iIntValue == 2 || iIntValue == 3) {
                return true;
            }
        }
        return false;
    }

    public /* synthetic */ e(boolean z, int i) {
        this.a = i;
        this.b = z;
    }

    public e(i0 i0Var) {
        this.a = 0;
        this.b = i0Var.a(Preview3AThreadCrashQuirk.class);
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 2:
                this.b = androidx.camera.camera2.internal.compat.quirk.b.a.b(TorchIsClosedAfterImageCapturingQuirk.class) != null;
                break;
            case 3:
                this.b = androidx.camera.core.internal.compat.quirk.a.a.b(SurfaceOrderQuirk.class) != null;
                break;
            default:
                this.b = ((StillCaptureFlashStopRepeatingQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(StillCaptureFlashStopRepeatingQuirk.class)) != null;
                break;
        }
    }
}
