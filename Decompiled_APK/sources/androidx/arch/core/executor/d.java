package androidx.arch.core.executor;

import android.app.Application;
import android.app.job.JobParameters;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Icon;
import android.icu.text.DecimalFormatSymbols;
import android.net.Network;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.PrecomputedText;
import android.view.DisplayCutout;
import android.view.ViewConfiguration;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.camera.core.RunnableC0193p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class d {
    public static Handler a(Looper looper) {
        return Handler.createAsync(looper);
    }

    public static Handler b(Looper looper) {
        return Handler.createAsync(looper);
    }

    public static String[] c(DecimalFormatSymbols decimalFormatSymbols) {
        return decimalFormatSymbols.getDigitStrings();
    }

    public static long d(PackageInfo packageInfo) {
        return packageInfo.getLongVersionCode();
    }

    public static Network e(JobParameters jobParameters) {
        return jobParameters.getNetwork();
    }

    public static String f() {
        String processName = Application.getProcessName();
        Intrinsics.checkNotNullExpressionValue(processName, "getProcessName()");
        return processName;
    }

    public static int g(Object obj) {
        return ((Icon) obj).getResId();
    }

    public static String h(Object obj) {
        return ((Icon) obj).getResPackage();
    }

    public static int i(DisplayCutout displayCutout) {
        return displayCutout.getSafeInsetBottom();
    }

    public static int j(DisplayCutout displayCutout) {
        return displayCutout.getSafeInsetLeft();
    }

    public static int k(DisplayCutout displayCutout) {
        return displayCutout.getSafeInsetRight();
    }

    public static int l(DisplayCutout displayCutout) {
        return displayCutout.getSafeInsetTop();
    }

    public static PrecomputedText.Params m(AppCompatTextView appCompatTextView) {
        return appCompatTextView.getTextMetricsParams();
    }

    public static int n(Object obj) {
        return ((Icon) obj).getType();
    }

    public static Uri o(Object obj) {
        return ((Icon) obj).getUri();
    }

    public static boolean p(Handler handler, RunnableC0193p runnableC0193p, long j) {
        return handler.postDelayed(runnableC0193p, "retry_token", j);
    }

    public static void q(TextView textView, int i) {
        textView.setFirstBaselineToTopHeight(i);
    }

    public static boolean r(ViewConfiguration viewConfiguration) {
        return viewConfiguration.shouldShowMenuShortcutsWhenKeyboardPresent();
    }
}
