package threatdetector.service;

import threatdetector.model.InputType;
import threatdetector.model.RuleHit;
import threatdetector.model.ScanItem;

public interface Rule  {
    /** Cette règle s'applique-t-elle à ce type d'entrée (URL / MESSAGE) ? */
    boolean appliesTo(InputType type);

    RuleHit evaluate(ScanItem item);

}
