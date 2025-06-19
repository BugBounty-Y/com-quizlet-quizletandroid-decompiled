package androidx.startup;

import android.content.Context;
import java.util.List;

/* loaded from: classes.dex */
public interface b {
    Object create(Context context);

    List dependencies();
}
