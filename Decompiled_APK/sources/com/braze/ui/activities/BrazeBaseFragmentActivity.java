package com.braze.ui.activities;

import androidx.fragment.app.I;
import com.braze.Braze;
import com.braze.BrazeInternal;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeBaseFragmentActivity extends I {
    @Override // androidx.fragment.app.I, android.app.Activity
    public void onPause() {
        super.onPause();
        BrazeInAppMessageManager.Companion.getInstance().unregisterInAppMessageManager(this);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onResume() {
        super.onResume();
        BrazeInAppMessageManager.Companion.getInstance().registerInAppMessageManager(this);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onStart() {
        super.onStart();
        if (BrazeInternal.INSTANCE.getConfigurationProvider(this).getShouldUseWindowFlagSecureInActivities()) {
            getWindow().setFlags(8192, 8192);
        }
        Braze.Companion.getInstance(this).openSession(this);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public void onStop() {
        super.onStop();
        Braze.Companion.getInstance(this).closeSession(this);
    }
}
