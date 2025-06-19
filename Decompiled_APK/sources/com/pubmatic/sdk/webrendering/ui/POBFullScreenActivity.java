package com.pubmatic.sdk.webrendering.ui;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.cache.a;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.Objects;

/* loaded from: classes2.dex */
public class POBFullScreenActivity extends Activity {
    public static final String ALLOW_ORIENTATION_CHANGE = "AllowOrientation";
    public static final String ENABLE_BACK_PRESS = "EnableBackPress";
    public static final String RENDERER_IDENTIFIER = "RendererIdentifier";
    public static final String REQUESTED_ORIENTATION = "RequestedOrientation";
    private ViewGroup a;
    private int b;
    private androidx.localbroadcastmanager.content.b c;
    private com.pubmatic.sdk.common.ui.d d;
    private com.pubmatic.sdk.common.ui.c e;
    private boolean g = false;

    @NonNull
    private BroadcastReceiver f = new b();

    public enum a {
        POB_CLOSE,
        POB_BACK_PRESS
    }

    public class b extends BroadcastReceiver {
        public b() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(@NonNull Context context, @NonNull Intent intent) {
            if (Integer.valueOf(intent.getIntExtra(POBFullScreenActivity.RENDERER_IDENTIFIER, 0)).equals(Integer.valueOf(POBFullScreenActivity.this.b))) {
                POBFullScreenActivity.this.onBroadcastReceived(intent);
            }
        }
    }

    public static void closeActivity(@NonNull Context context, int i) {
        Intent intent = new Intent(a.POB_CLOSE.name());
        intent.putExtra(RENDERER_IDENTIFIER, i);
        sendBroadcast(context, intent);
    }

    public static void sendBroadcast(@NonNull Context context, @NonNull Intent intent) {
        androidx.localbroadcastmanager.content.b.a(context).c(intent);
    }

    public static void startActivity(@NonNull Context context, @NonNull Intent intent) {
        intent.setClass(context, POBFullScreenActivity.class);
        intent.addFlags(268435456);
        context.startActivity(intent);
    }

    public static void startFullScreenActivity(@NonNull Context context, int i, @NonNull com.pubmatic.sdk.common.base.c cVar, int i2) {
        Intent intent = new Intent();
        intent.putExtra(REQUESTED_ORIENTATION, i);
        intent.putExtra(RENDERER_IDENTIFIER, i2);
        intent.putExtra(ENABLE_BACK_PRESS, false);
        if (!cVar.isVideo()) {
            intent.putExtra(ALLOW_ORIENTATION_CHANGE, Boolean.FALSE);
        }
        startActivity(context, intent);
    }

    public static void updateBackButtonState(@NonNull Context context, int i, boolean z) {
        Intent intent = new Intent(a.POB_BACK_PRESS.name());
        intent.putExtra(RENDERER_IDENTIFIER, i);
        intent.putExtra(ENABLE_BACK_PRESS, z);
        sendBroadcast(context, intent);
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        if (this.g) {
            super.onBackPressed();
        }
    }

    public void onBroadcastReceived(@NonNull Intent intent) {
        String action = intent.getAction();
        if (Objects.equals(action, a.POB_CLOSE.name())) {
            finish();
        } else if (Objects.equals(action, a.POB_BACK_PRESS.name())) {
            this.g = intent.getBooleanExtra(ENABLE_BACK_PRESS, false);
        }
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = getIntent();
        int intExtra = intent.getIntExtra(REQUESTED_ORIENTATION, com.pubmatic.sdk.common.utility.o.getDeviceOrientation(getApplicationContext()));
        boolean booleanExtra = intent.getBooleanExtra(ALLOW_ORIENTATION_CHANGE, true);
        this.g = intent.getBooleanExtra(ENABLE_BACK_PRESS, false);
        int intExtra2 = intent.getIntExtra(RENDERER_IDENTIFIER, 0);
        this.b = intExtra2;
        if (intExtra2 != 0) {
            a.C0008a c0008aPopStoredAdView = com.pubmatic.sdk.common.i.getAdViewCacheService().popStoredAdView(Integer.valueOf(this.b));
            if (c0008aPopStoredAdView == null) {
                POBLog.error("POBFullScreenActivity", "Unable to retrieve stored ad view config for %s", Integer.valueOf(this.b));
                finish();
                return;
            }
            this.a = (ViewGroup) c0008aPopStoredAdView.getAdView();
            this.d = c0008aPopStoredAdView.getEventListener();
            c0008aPopStoredAdView.getBackPressListener();
            this.a.setId(com.pubmatic.sdk.webrendering.e.pob_modal_view);
            setContentView(this.a);
            androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a(getApplicationContext());
            this.c = bVarA;
            bVarA.b(this.f, a());
            com.pubmatic.sdk.common.ui.d dVar = this.d;
            if (dVar != null) {
                dVar.onCreate(this);
            }
        }
        if (booleanExtra) {
            setRequestedOrientation(-1);
        } else {
            a(intExtra);
        }
    }

    @Override // android.app.Activity
    public void onDestroy() {
        ViewGroup viewGroup = this.a;
        if (viewGroup != null && (viewGroup.getParent() instanceof ViewGroup)) {
            ((ViewGroup) this.a.getParent()).removeView(this.a);
            this.a.removeAllViews();
        }
        super.onDestroy();
        setRequestedOrientation(-1);
        com.pubmatic.sdk.common.ui.d dVar = this.d;
        if (dVar != null) {
            dVar.onDestroy();
        }
        androidx.localbroadcastmanager.content.b bVar = this.c;
        if (bVar != null) {
            bVar.d(this.f);
        }
    }

    private IntentFilter a() {
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(a.POB_CLOSE.name());
        intentFilter.addAction(a.POB_BACK_PRESS.name());
        return intentFilter;
    }

    private void a(int i) {
        if (i == 0) {
            setRequestedOrientation(-1);
        } else if (i == 2) {
            setRequestedOrientation(6);
        } else if (i == 1) {
            setRequestedOrientation(7);
        }
    }

    public static void startFullScreenActivity(@NonNull Context context, boolean z, int i) {
        Intent intent = new Intent();
        intent.putExtra(RENDERER_IDENTIFIER, i);
        if (z) {
            intent.putExtra(ENABLE_BACK_PRESS, false);
        } else {
            intent.putExtra(ALLOW_ORIENTATION_CHANGE, Boolean.FALSE);
        }
        startActivity(context, intent);
    }
}
