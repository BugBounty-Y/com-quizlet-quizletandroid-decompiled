package androidx.appcompat.widget;

import android.app.Activity;
import android.content.ClipData;
import android.os.Build;
import android.text.Selection;
import android.text.Spannable;
import android.view.DragEvent;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.core.view.C1046f;
import androidx.core.view.InterfaceC1044e;

/* loaded from: classes.dex */
public abstract class F {
    public static boolean a(@NonNull DragEvent dragEvent, @NonNull TextView textView, @NonNull Activity activity) {
        InterfaceC1044e hVar;
        activity.requestDragAndDropPermissions(dragEvent);
        int offsetForPosition = textView.getOffsetForPosition(dragEvent.getX(), dragEvent.getY());
        textView.beginBatchEdit();
        try {
            Selection.setSelection((Spannable) textView.getText(), offsetForPosition);
            ClipData clipData = dragEvent.getClipData();
            if (Build.VERSION.SDK_INT >= 31) {
                hVar = new com.google.android.gms.auth.api.signin.internal.h(clipData, 3);
            } else {
                C1046f c1046f = new C1046f();
                c1046f.b = clipData;
                c1046f.c = 3;
                hVar = c1046f;
            }
            androidx.core.view.V.k(textView, hVar.build());
            textView.endBatchEdit();
            return true;
        } catch (Throwable th) {
            textView.endBatchEdit();
            throw th;
        }
    }

    public static boolean b(@NonNull DragEvent dragEvent, @NonNull View view, @NonNull Activity activity) {
        InterfaceC1044e hVar;
        activity.requestDragAndDropPermissions(dragEvent);
        ClipData clipData = dragEvent.getClipData();
        if (Build.VERSION.SDK_INT >= 31) {
            hVar = new com.google.android.gms.auth.api.signin.internal.h(clipData, 3);
        } else {
            C1046f c1046f = new C1046f();
            c1046f.b = clipData;
            c1046f.c = 3;
            hVar = c1046f;
        }
        androidx.core.view.V.k(view, hVar.build());
        return true;
    }
}
