package androidx.core.content;

import android.content.Intent;
import com.quizlet.data.model.m2;
import java.io.Serializable;
import java.util.ArrayList;

/* loaded from: classes.dex */
public abstract class e {
    public static ArrayList a(Intent intent, String str, Class cls) {
        return intent.getParcelableArrayListExtra(str, cls);
    }

    public static Object b(Intent intent, String str, Class cls) {
        return intent.getParcelableExtra(str, cls);
    }

    public static Serializable c(Intent intent) {
        return intent.getSerializableExtra("source", m2.class);
    }
}
