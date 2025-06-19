package org.prebid.mobile.rendering.views.browser;

import android.graphics.Color;
import android.os.Handler;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TableLayout;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
final class BrowserControls extends TableLayout {
    public static final int j = Color.rgb(43, 47, 50);
    public Button a;
    public Button b;
    public Button c;
    public Button d;
    public Button e;
    public LinearLayout f;
    public LinearLayout g;
    public Handler h;
    public BrowserControlsEventsListener i;

    public static void a(Button button) {
        button.setHeight((int) (Utils.a * 50.0f));
        button.setWidth((int) (Utils.a * 50.0f));
    }
}
