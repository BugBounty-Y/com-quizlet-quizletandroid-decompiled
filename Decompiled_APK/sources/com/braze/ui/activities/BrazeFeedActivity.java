package com.braze.ui.activities;

import android.os.Bundle;
import com.braze.BrazeInternal;
import com.braze.ui.R$layout;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public class BrazeFeedActivity extends BrazeBaseFragmentActivity {
    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (BrazeInternal.INSTANCE.getConfigurationProvider(this).getShouldUseWindowFlagSecureInActivities()) {
            getWindow().setFlags(8192, 8192);
        }
        setContentView(R$layout.com_braze_feed_activity);
    }
}
