package androidx.fragment.app;

import android.util.Log;
import androidx.activity.result.ActivityResult;
import java.util.ArrayList;
import java.util.Map;

/* loaded from: classes.dex */
public final class U implements androidx.activity.result.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1136h0 b;

    public /* synthetic */ U(int i, AbstractC1136h0 abstractC1136h0) {
        this.a = i;
        this.b = abstractC1136h0;
    }

    @Override // androidx.activity.result.a
    public final void a(Object obj) {
        switch (this.a) {
            case 0:
                Map map = (Map) obj;
                String[] strArr = (String[]) map.keySet().toArray(new String[0]);
                ArrayList arrayList = new ArrayList(map.values());
                int[] iArr = new int[arrayList.size()];
                for (int i = 0; i < arrayList.size(); i++) {
                    iArr[i] = ((Boolean) arrayList.get(i)).booleanValue() ? 0 : -1;
                }
                AbstractC1136h0 abstractC1136h0 = this.b;
                FragmentManager$LaunchedFragmentInfo fragmentManager$LaunchedFragmentInfo = (FragmentManager$LaunchedFragmentInfo) abstractC1136h0.G.pollFirst();
                if (fragmentManager$LaunchedFragmentInfo == null) {
                    Log.w("FragmentManager", "No permissions were requested for " + this);
                    break;
                } else {
                    q0 q0Var = abstractC1136h0.c;
                    String str = fragmentManager$LaunchedFragmentInfo.a;
                    Fragment fragmentC = q0Var.c(str);
                    if (fragmentC == null) {
                        Log.w("FragmentManager", "Permission request result delivered for unknown Fragment " + str);
                        break;
                    } else {
                        fragmentC.onRequestPermissionsResult(fragmentManager$LaunchedFragmentInfo.b, strArr, iArr);
                        break;
                    }
                }
            case 1:
                ActivityResult activityResult = (ActivityResult) obj;
                AbstractC1136h0 abstractC1136h02 = this.b;
                FragmentManager$LaunchedFragmentInfo fragmentManager$LaunchedFragmentInfo2 = (FragmentManager$LaunchedFragmentInfo) abstractC1136h02.G.pollLast();
                if (fragmentManager$LaunchedFragmentInfo2 == null) {
                    Log.w("FragmentManager", "No Activities were started for result for " + this);
                    break;
                } else {
                    q0 q0Var2 = abstractC1136h02.c;
                    String str2 = fragmentManager$LaunchedFragmentInfo2.a;
                    Fragment fragmentC2 = q0Var2.c(str2);
                    if (fragmentC2 == null) {
                        Log.w("FragmentManager", "Activity result delivered for unknown Fragment " + str2);
                        break;
                    } else {
                        fragmentC2.onActivityResult(fragmentManager$LaunchedFragmentInfo2.b, activityResult.a, activityResult.b);
                        break;
                    }
                }
            default:
                ActivityResult activityResult2 = (ActivityResult) obj;
                AbstractC1136h0 abstractC1136h03 = this.b;
                FragmentManager$LaunchedFragmentInfo fragmentManager$LaunchedFragmentInfo3 = (FragmentManager$LaunchedFragmentInfo) abstractC1136h03.G.pollFirst();
                if (fragmentManager$LaunchedFragmentInfo3 == null) {
                    Log.w("FragmentManager", "No IntentSenders were started for " + this);
                    break;
                } else {
                    q0 q0Var3 = abstractC1136h03.c;
                    String str3 = fragmentManager$LaunchedFragmentInfo3.a;
                    Fragment fragmentC3 = q0Var3.c(str3);
                    if (fragmentC3 == null) {
                        Log.w("FragmentManager", "Intent Sender result delivered for unknown Fragment " + str3);
                        break;
                    } else {
                        fragmentC3.onActivityResult(fragmentManager$LaunchedFragmentInfo3.b, activityResult2.a, activityResult2.b);
                        break;
                    }
                }
        }
    }
}
