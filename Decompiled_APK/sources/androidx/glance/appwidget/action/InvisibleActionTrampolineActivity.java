package androidx.glance.appwidget.action;

import android.app.Activity;
import android.os.Bundle;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class InvisibleActionTrampolineActivity extends Activity {
    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        g.f(this, getIntent());
    }
}
