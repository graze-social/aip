#!/bin/bash
# PostgreSQL Integration Test Script
# This script sets up PostgreSQL in Docker and runs the test suite

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
POSTGRES_CONTAINER="aip_postgres"
TEST_DATABASE="aip_test"
POSTGRES_PORT="5433"
MAX_WAIT_TIME=60

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if .env.test exists
check_env_file() {
    if [[ ! -f ".env.test" ]]; then
        print_warning ".env.test not found. Creating default test environment file..."
        cat > .env.test << EOF
OAUTH_SIGNING_KEYS=did:key:z42tuGiCa7bTnxvCAizt7oSjUH55PAVDnx4Ep21ppbpB5R3N
ATPROTO_OAUTH_SIGNING_KEYS=did:key:z42tuGiCa7bTnxvCAizt7oSjUH55PAVDnx4Ep21ppbpB5R3N
DPOP_NONCE_SEED="lkajhsdlkjasdlkjasdlkjasdlkj"
STORAGE_BACKEND=postgres
DATABASE_URL=postgresql://aip:aip_dev_password@localhost:5433/aip_test
EXTERNAL_BASE=http://localhost:8080
HTTP_PORT=8050
PLC_HOSTNAME=plc.directory
HTTP_CLIENT_TIMEOUT=10s
RUST_LOG=aip=debug,info
EOF
        print_success "Created .env.test file"
    fi
}

# Function to clean up existing container
cleanup_container() {
    if docker ps -a --format 'table {{.Names}}' | grep -q "^${POSTGRES_CONTAINER}$"; then
        print_info "Stopping and removing existing PostgreSQL container..."
        docker stop $POSTGRES_CONTAINER > /dev/null 2>&1 || true
        docker rm $POSTGRES_CONTAINER > /dev/null 2>&1 || true
        print_success "Cleaned up existing container"
    fi
}

# Function to start PostgreSQL container
start_postgres() {
    print_info "Starting PostgreSQL container..."
    
    if command -v docker-compose &> /dev/null && [[ -f "docker-compose.yml" ]]; then
        # Use docker-compose if available
        print_info "Using docker-compose to start PostgreSQL..."
        docker-compose up -d postgres
    else
        # Use docker run as fallback
        print_info "Using docker run to start PostgreSQL..."
        docker run -d \
            --name $POSTGRES_CONTAINER \
            -e POSTGRES_DB=$TEST_DATABASE \
            -e POSTGRES_USER=aip \
            -e POSTGRES_PASSWORD=aip_dev_password \
            -e POSTGRES_INITDB_ARGS="--encoding=UTF8 --locale=C" \
            -p $POSTGRES_PORT:5432 \
            -v aip_postgres_data:/var/lib/postgresql/data \
            postgres:17-alpine > /dev/null
    fi
    
    print_success "PostgreSQL container started"
}

# Function to wait for PostgreSQL to be ready
wait_for_postgres() {
    print_info "Waiting for PostgreSQL to be ready..."
    
    local count=0
    while [ $count -lt $MAX_WAIT_TIME ]; do
        if docker exec $POSTGRES_CONTAINER pg_isready -U aip -d $TEST_DATABASE > /dev/null 2>&1; then
            print_success "PostgreSQL is ready!"
            return 0
        fi
        
        printf "."
        sleep 2
        count=$((count + 2))
    done
    
    print_error "PostgreSQL failed to start within $MAX_WAIT_TIME seconds"
    print_info "Container logs:"
    docker logs $POSTGRES_CONTAINER
    exit 1
}

# Function to load environment variables
load_environment() {
    print_info "Loading test environment variables..."
    
    if [[ -f ".env.test" ]]; then
        export $(cat .env.test | grep -v '^#' | xargs)
        print_success "Environment variables loaded"
    else
        print_error ".env.test file not found"
        exit 1
    fi
}

# Function to verify database connection
verify_connection() {
    print_info "Verifying database connection..."
    
    if docker exec $POSTGRES_CONTAINER psql -U aip -d $TEST_DATABASE -c "SELECT version();" > /dev/null 2>&1; then
        local pg_version=$(docker exec $POSTGRES_CONTAINER psql -U aip -d $TEST_DATABASE -t -c "SELECT version();" | xargs)
        print_success "Database connection verified: $pg_version"
    else
        print_error "Failed to connect to database"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_info "Running tests with PostgreSQL backend..."
    
    # Create test directories if they don't exist
    mkdir -p ./test_badges
    
    # Run the tests
    if cargo test "$@"; then
        print_success "All tests passed!"
    else
        print_error "Some tests failed"
        return 1
    fi
}

# Function to cleanup
cleanup() {
    print_info "Cleaning up..."
    
    if command -v docker-compose &> /dev/null && [[ -f "docker-compose.yml" ]]; then
        docker-compose down > /dev/null 2>&1 || true
    else
        docker stop $POSTGRES_CONTAINER > /dev/null 2>&1 || true
        docker rm $POSTGRES_CONTAINER > /dev/null 2>&1 || true
    fi
    
    # Clean up test artifacts
    rm -rf ./test_badges
    
    print_success "Cleanup completed"
}

# Function to show usage
usage() {
    echo "Usage: $0 [OPTIONS] [TEST_ARGS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -k, --keep     Keep PostgreSQL container running after tests"
    echo "  -c, --clean    Clean up containers and volumes before starting"
    echo "  -v, --verbose  Enable verbose output"
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all tests"
    echo "  $0 storage::tests           # Run only storage tests"
    echo "  $0 --keep                   # Run tests and keep container running"
    echo "  $0 --clean --verbose        # Clean start with verbose output"
    echo "  $0 -- --nocapture           # Pass --nocapture to cargo test"
}

# Parse command line arguments
KEEP_CONTAINER=false
CLEAN_START=false
VERBOSE=false
TEST_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -k|--keep)
            KEEP_CONTAINER=true
            shift
            ;;
        -c|--clean)
            CLEAN_START=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --)
            shift
            TEST_ARGS+=("$@")
            break
            ;;
        *)
            TEST_ARGS+=("$1")
            shift
            ;;
    esac
done

# Enable verbose output if requested
if [[ "$VERBOSE" == "true" ]]; then
    set -x
fi

# Main execution
main() {
    print_info "Starting PostgreSQL integration tests..."
    
    # Pre-flight checks
    check_docker
    check_env_file
    
    # Clean up if requested
    if [[ "$CLEAN_START" == "true" ]]; then
        print_info "Performing clean start..."
        cleanup_container
        if command -v docker-compose &> /dev/null && [[ -f "docker-compose.yml" ]]; then
            docker-compose down -v > /dev/null 2>&1 || true
        fi
    fi
    
    # Setup
    cleanup_container
    start_postgres
    wait_for_postgres
    load_environment
    verify_connection
    
    # Run tests
    local test_result=0
    run_tests "${TEST_ARGS[@]}" || test_result=$?
    
    # Cleanup unless keeping container
    if [[ "$KEEP_CONTAINER" == "false" ]]; then
        cleanup
    else
        print_info "PostgreSQL container is still running for debugging"
        print_info "Connect with: docker exec -it $POSTGRES_CONTAINER psql -U aip -d $TEST_DATABASE"
        print_info "Stop with: docker stop $POSTGRES_CONTAINER"
    fi
    
    if [[ $test_result -eq 0 ]]; then
        print_success "PostgreSQL integration tests completed successfully!"
    else
        print_error "PostgreSQL integration tests failed!"
        exit $test_result
    fi
}

# Trap to ensure cleanup on script exit
trap 'if [[ "$KEEP_CONTAINER" == "false" ]]; then cleanup; fi' EXIT INT TERM

# Run main function
main "$@"