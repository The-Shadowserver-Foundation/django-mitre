class MitreAttackIdLookup {
    constructor($form) {
        this.$form = $form;

        this.init();
    }

    init() {
        var self = this;

        // Look input box
        var $input = $(this.$form.find('input')[0]);

        function getContext() {
            // Determine the identifier's context
            var urlSchemePattern = /^\/mitre\/([^\/]+)\/.*$/;
            var match = window.location.pathname.match(urlSchemePattern);
            if (match && match.length > 1) {
                var context = match[1];
            } else {
                // Use attack by default
                var context = 'attack';
            }
            return context;
        }

        // Register form intercept
        this.$form.submit(function (event) {
            var id = $input.val();
            var context = getContext();

            // Note, currently not used outside the context of this application's url path space.
            window.location.href = `/mitre/${context}/redirect-id/${id}/`;
            event.preventDefault();
        });
    }

}

class MitreAttackMatrix {
    constructor($matrix, $platformSelect) {
        this.$matrix = $matrix;
        this.$platformSelect = $platformSelect;

        this.init();
    }

    getPlatform() {
        // Use the url query-string value as the canonical source of truth
        var url = new URL(window.location);
        return url.searchParams.has('platform') ? url.searchParams.get('platform') : 'All';
    }

    init() {
        var self = this;

        // Initialize sub-technique button click events
        var $buttons = this.$matrix.find('ul.major_techniques > li > button');
        $buttons.each((i, elem) => {
            var $elem = $(elem);
            $elem.click(function () {
                var $target = $(this).parent().find('ul');
                if ($target.is(':visible')) {
                    $(this).removeClass('glyphicon-minus-sign');
                    $(this).addClass('glyphicon-plus-sign');
                    if ($(this).text().trim().length) {
                        $(this).text('+');
                    }
                } else {
                    $(this).removeClass('glyphicon-plus-sign');
                    $(this).addClass('glyphicon-minus-sign');
                    if ($(this).text().trim().length) {
                        $(this).text('-');
                    }
                }
                $target.toggle();
            });
        });

        // Initialize platform selection event handler
        this.$platformSelect.change(function () {
            var $select = $(this);
            $select.find('option:selected').each((i, elem) => {
                var url = new URL(window.location);
                var state = {"platform": elem.value};

                // Show/Hide by platform class
                self.renderMatrix(elem.value);

                // Set the platform in the state and url
                if ( elem.value == 'All' ) {
                    url.searchParams.delete('platform');
                } else {
                    url.searchParams.set('platform', elem.value);
                }
                history.pushState(state, document.title, url);
            });
        });

        // Initialize popstate event handler (i.e. back/forward buttons)
        $(window).on("popstate", function (ev) {
            self.renderFromState(history.state);
        });

        // Initialize the matrix from url query string
        if (typeof app !== 'undefined') {
            app.$elem.on('app:inited', () => { self.initRenderFromURL(); });
            app.$elem.on('app:changed', () => { self.initRenderFromURL(); });
        } else {
            // Not within a project containing shared shadowserver code
            self.initRenderFromURL();
        }
    }

    renderMatrix(platform) {
        if ( platform == 'All' ) {
            this.$matrix.find('li').show();
        } else {
            this.$matrix.find('li').each((i, elem) => {
                var $elem = $(elem);
                if ( !$elem.hasClass("platform-" + platform) ) {
                    $elem.hide();
                } else {
                    $elem.show();
                }
            });
        }
    }

    renderFromState(state) {
        var platform = state.platform;
        // Set the selection to the state value
        this.$platformSelect.val(platform);
        // Display the matrix
        this.renderMatrix(platform);
    }

    initRenderFromURL() {
        var platform = this.getPlatform();
        // Set the current state for history
        history.replaceState({"platform": platform}, '')
        // Set the selection to the state value
        this.$platformSelect.val(platform);
        // Display the matrix
        this.renderMatrix(platform);
    }

}

$(function(){
    initMitreAttackMatrix();
    initMitreAttackIdLookup();
});

function initMitreAttackMatrix() {
    var $matrix = $('table#mitreattack-matrix');
    var $matrixPlatformSelection = $('#mitreattack-matrix-platform-selector');
    // Verify we are on the page that uses this feature
    if ( $matrixPlatformSelection.length ) {
        new MitreAttackMatrix($matrix, $matrixPlatformSelection);
    }
};

function initMitreAttackIdLookup() {
    var $form = $('#mitreattack-lookup-by-id');
    // Verify we are on the page that uses this feature
    if ( $form.length ) {
        new MitreAttackIdLookup($form);
    }
};
