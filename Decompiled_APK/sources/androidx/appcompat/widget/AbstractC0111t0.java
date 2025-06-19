package androidx.appcompat.widget;

import android.widget.AbsListView;
import java.lang.reflect.Field;

/* renamed from: androidx.appcompat.widget.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0111t0 {
    public static final Field a;

    static {
        Field declaredField = null;
        try {
            declaredField = AbsListView.class.getDeclaredField("mIsChildViewEnabled");
            declaredField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        a = declaredField;
    }
}
