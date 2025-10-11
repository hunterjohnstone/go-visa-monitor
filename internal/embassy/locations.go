package embassy

import (
	"go-visa-monitor/internal/config"
)

var Embassies = map[string]config.EmbassyConfig{
	// just gonna start with windhoek
	"windhoek": {
		Name:         "Windhoek",
		LocationCode: "wind",
		RealmID:      "1490",
		CategoryID:   "3603",
		URL:          "https://service2.diplo.de/rktermin/extern/appointment_showMonth.do",
	},
	// "new_dehli_passport_pickup": {
	// 	Name:         "New Dehli Passport Pickip",
	// 	LocationCode: "newd",
	// 	RealmID:      "1144",
	// 	CategoryID:   "2481",
	// 	URL:          "https://service2.diplo.de/rktermin/extern/appointment_showMonth.do",
	// },
	"istanbul_Belge_Düzenleme_ve_Tasdik_İşlemleri": {
		Name:         "Istanbul Document Attestation Appointments",
		LocationCode: "ista",
		RealmID:      "559",
		CategoryID:   "3579",
		URL:          "https://service2.diplo.de/rktermin/extern/appointment_showMonth.do",
	},
	"accra": {
		Name:         "accre",
		LocationCode: "accr",
		RealmID:      "279",
		CategoryID:   "2978",
		URL:          "https://service2.diplo.de/rktermin/extern/appointment_showMonth.do",
	},
}

//https://service2.diplo.de/rktermin/extern/appointment_showMonth.do?locationCode=accr&realmId=279&categoryId=2978
