package androidx.camera.core.impl.utils.executor;

import android.view.View;
import androidx.activity.N;
import com.quizlet.quizletandroid.R;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class i {
    public static volatile e a;

    public static int a(com.quizlet.quizletandroid.util.j permissionAccess, boolean z) {
        Intrinsics.checkNotNullParameter(permissionAccess, "permissionAccess");
        int iOrdinal = permissionAccess.ordinal();
        if (iOrdinal == 0) {
            return z ? R.string.visibility_permission_picker_justme : R.string.editability_permission_picker_justme;
        }
        if (iOrdinal == 1) {
            return z ? R.string.visibility_permission_picker_password : R.string.editability_permission_picker_password;
        }
        if (iOrdinal == 2) {
            return z ? R.string.visibility_permission_picker_everyone : R.string.editability_permission_picker_everyone;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static final int b(DayOfWeek dayOfWeek) {
        Intrinsics.checkNotNullParameter(dayOfWeek, "<this>");
        switch (com.quizlet.features.achievements.extensions.a.a[dayOfWeek.ordinal()]) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
            case 4:
                return 4;
            case 5:
                return 5;
            case 6:
                return 6;
            case 7:
                return 7;
            default:
                throw new NoWhenBranchMatchedException();
        }
    }

    public static final boolean c(LocalDate localDate, List listOfStreakDates) {
        Intrinsics.checkNotNullParameter(localDate, "<this>");
        Intrinsics.checkNotNullParameter(listOfStreakDates, "listOfStreakDates");
        if (listOfStreakDates != null && listOfStreakDates.isEmpty()) {
            return false;
        }
        Iterator it2 = listOfStreakDates.iterator();
        while (it2.hasNext()) {
            LocalDate localDate2 = (LocalDate) it2.next();
            if (localDate2.getYear() == localDate.getYear() && localDate2.getMonth() == localDate.getMonth() && localDate2.getDayOfMonth() == localDate.getDayOfMonth()) {
                return true;
            }
        }
        return false;
    }

    public static final void d(View view, N onBackPressedDispatcherOwner) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(onBackPressedDispatcherOwner, "onBackPressedDispatcherOwner");
        view.setTag(R.id.view_tree_on_back_pressed_dispatcher_owner, onBackPressedDispatcherOwner);
    }
}
