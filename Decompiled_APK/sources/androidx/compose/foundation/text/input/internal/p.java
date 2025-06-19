package androidx.compose.foundation.text.input.internal;

import android.credentials.ClearCredentialStateRequest;
import android.os.Bundle;
import android.text.GraphemeClusterSegmentFinder;
import android.text.SegmentFinder;
import android.text.TextPaint;
import android.view.inputmethod.HandwritingGesture;
import android.view.inputmethod.SelectGesture;

/* loaded from: classes.dex */
public abstract /* synthetic */ class p {
    public static /* synthetic */ ClearCredentialStateRequest e(Bundle bundle) {
        return new ClearCredentialStateRequest(bundle);
    }

    public static /* synthetic */ GraphemeClusterSegmentFinder o(CharSequence charSequence, TextPaint textPaint) {
        return new GraphemeClusterSegmentFinder(charSequence, textPaint);
    }

    public static /* bridge */ /* synthetic */ SegmentFinder p(Object obj) {
        return (SegmentFinder) obj;
    }

    public static /* bridge */ /* synthetic */ HandwritingGesture q(Object obj) {
        return (HandwritingGesture) obj;
    }

    public static /* bridge */ /* synthetic */ SelectGesture r(Object obj) {
        return (SelectGesture) obj;
    }

    public static /* synthetic */ void w() {
    }

    public static /* bridge */ /* synthetic */ boolean y(Object obj) {
        return obj instanceof SelectGesture;
    }
}
