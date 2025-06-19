package assistantMode.utils.classification;

import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.DBGroup;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final Set a;
    public static final Set b;
    public static final Set c;
    public static final Set d;
    public static final Set e;
    public static final Set f;
    public static final Set g;
    public static final Set h;
    public static final Set i;

    static {
        String[] elements = {"king", "queen", "president", OTVendorListMode.GENERAL, "archduke", "archduchess", "emperor", "emperess", "csar", "tsar", "tzar"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
        String[] elements2 = {"ruler", "philosopher", "minister", "chief", "father", "explorer", "governor", "commander", "secretary", "author", "writer", "dictator", "senator", "inventor", "scientist", "negotiator", "liberator", "poet", "pharaoh", "conquistador", "statesman", "teacher", "duke", "duchess", "magistrate", "caliph", "knight", "wife", "mother", "father", "scion", "mayor", "chancellor", "reporter", "cartoonist", "muckraker", "lawyer", "doctor", "nurse", "navigator", "sailor", "soldier", "sergeant", "captain", "lieutenant", "admiral", "physicist", "engineer", "mathemetician", "husband", "son", "actor", "evolutionist", "thinker", "preacher", "bishop", "grandson", "daughter", "mathematician", "composer", "cosmonaut", "historian", "scholar", "architect", "astronomer", "astronaut", "prophet", "journalist", "activist"};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        b = C4933y.T(elements2);
        String[] elements3 = {"who", "leader", "leaders", "he", AssociationNames.PERSON, "led", "created", "wrote", "founded", "founder", "established", "became", "his", "wanted", "built", "developed", "invented", "ruled", "helped", "born", "discovered", "life", "criticized", "assassinated", "organized", "whose", "elected", "rule", "supported", "woman", "lived", "worked", "killed", "death", "served", "owned", "she", "claimed", "painted", "protest", "promoted", "lord", "trained", "traveled", "studied", "died", "advocated", "improved", "merchant", "commanded", "whom", "suffagette", "priest", "healer", "designed"};
        Intrinsics.checkNotNullParameter(elements3, "elements");
        c = C4933y.T(elements3);
        String[] elements4 = {"war", "battle", "conflict", "fought", "victory", "turning point", "defeated", "attack", "bloodiest", "struggle", "lasting", "began", "ended", "decisive", "offensive", "event", "fight", "attacked", "lasted", "period", "revolution", "revolt", "revolts", "genocide", "famine", "flood"};
        Intrinsics.checkNotNullParameter(elements4, "elements");
        d = C4933y.T(elements4);
        String[] elements5 = {"declaration", "treaty", "bill", "valitution", "covenant", "proclamation", "agreement", "concordance", "law", "deal", "pact", "act", "acts", "statute", "decree", "charter", "amendment", "papers", "accords", "resolution", "petition", "policy", "manifesto", "order", "edict", "plan", "code", "system"};
        Intrinsics.checkNotNullParameter(elements5, "elements");
        e = C4933y.T(elements5);
        String[] elements6 = {"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"};
        Intrinsics.checkNotNullParameter(elements6, "elements");
        f = C4933y.T(elements6);
        String[] elements7 = {"st", "nd", "rd", "th"};
        Intrinsics.checkNotNullParameter(elements7, "elements");
        g = C4933y.T(elements7);
        String[] elements8 = {"organization", "congress", "church", "kingdom", "empire", "state", "nation", "society", "party", DBGroup.TABLE_NAME, "bloc", "conference", "forces", "movement", "community", "commune", "revolutionaries", "supporters", "assembly", "coalition", "bureau", "family", "committee", "city"};
        Intrinsics.checkNotNullParameter(elements8, "elements");
        h = C4933y.T(elements8);
        String[] elements9 = {"theory", "hypothesis", "religion"};
        Intrinsics.checkNotNullParameter(elements9, "elements");
        i = C4933y.T(elements9);
    }
}
