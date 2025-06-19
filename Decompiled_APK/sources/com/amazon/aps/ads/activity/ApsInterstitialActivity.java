package com.amazon.aps.ads.activity;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import assistantMode.experiments.a;
import com.amazon.aps.ads.c;
import com.amazon.device.ads.DTBAdUtil;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;

@Metadata
/* loaded from: classes.dex */
public class ApsInterstitialActivity extends Activity {
    public final String a = "ApsInterstitialActivity";

    public ApsInterstitialActivity() {
        new LinearLayout.LayoutParams(DTBAdUtil.sizeToDevicePixels(24), DTBAdUtil.sizeToDevicePixels(24)).setMargins(DTBAdUtil.sizeToDevicePixels(14), DTBAdUtil.sizeToDevicePixels(14), 0, 0);
        l.b(new a(this, 2));
    }

    @Override // android.app.Activity
    public final void onBackPressed() {
        try {
            finish();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute onBackPressed method", e);
        }
    }

    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        try {
            String str = this.a;
            try {
                requestWindowFeature(1);
                getWindow().setFlags(1024, 1024);
                setContentView(R.layout.aps_interstitial_activity);
                c.a();
            } catch (RuntimeException e) {
                c.b(str, Intrinsics.k(e, "Error in calling the initActivity: "));
            }
            com.amazon.aps.shared.a.e(1, 1, "Fail to create ApsInterstitialActivity as the ad view is null", null);
            finish();
        } catch (RuntimeException e2) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to create ApsInterstitialActivity", e2);
            finish();
        }
    }

    @Override // android.app.Activity
    public final void onDestroy() {
        try {
            RelativeLayout relativeLayout = (RelativeLayout) findViewById(R.id.inter_container);
            if (relativeLayout != null) {
                relativeLayout.removeView(null);
            }
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to remove DTBAdView on Activity Destroy", e);
        }
        super.onDestroy();
    }
}
