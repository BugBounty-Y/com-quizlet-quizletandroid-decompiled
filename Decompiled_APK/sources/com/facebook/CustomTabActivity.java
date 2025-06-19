package com.facebook;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import com.facebook.internal.C1549d;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class CustomTabActivity extends Activity {
    public C1549d a;

    @Override // android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i2 == 0) {
            Intent intent2 = new Intent("CustomTabActivity.action_customTabRedirect");
            intent2.putExtra("CustomTabMainActivity.extra_url", getIntent().getDataString());
            androidx.localbroadcastmanager.content.b.a(this).c(intent2);
            C1549d c1549d = new C1549d(this, 3);
            androidx.localbroadcastmanager.content.b.a(this).b(c1549d, new IntentFilter("CustomTabActivity.action_destroy"));
            this.a = c1549d;
        }
    }

    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = new Intent(this, (Class<?>) CustomTabMainActivity.class);
        intent.setAction("CustomTabActivity.action_customTabRedirect");
        intent.putExtra("CustomTabMainActivity.extra_url", getIntent().getDataString());
        intent.addFlags(603979776);
        startActivityForResult(intent, 2);
    }

    @Override // android.app.Activity
    public final void onDestroy() {
        C1549d c1549d = this.a;
        if (c1549d != null) {
            androidx.localbroadcastmanager.content.b.a(this).d(c1549d);
        }
        super.onDestroy();
    }
}
