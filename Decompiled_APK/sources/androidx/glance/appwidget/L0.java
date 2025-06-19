package androidx.glance.appwidget;

import android.os.Build;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public abstract class L0 {
    public static final AtomicBoolean a = new AtomicBoolean(false);

    public static void a() {
        if (Build.VERSION.SDK_INT < 29 || !a.get()) {
            return;
        }
        M0.a.b("GlanceAppWidget::update", 0);
    }
}
